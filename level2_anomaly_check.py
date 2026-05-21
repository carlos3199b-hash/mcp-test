"""
Level 2 — AI-Powered Anomaly Checker
======================================
Same scheduled trigger as Level 1, but instead of hardcoded threshold logic,
raw metrics are passed to Claude which decides what is anomalous and writes
a plain English narrative summary. Catches patterns you didn't write rules for.

Extra dependency on top of Level 1:
  pip install anthropic

Add to your .env:
  ANTHROPIC_API_KEY=sk-ant-...
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timedelta, timezone

import anthropic
import httpx
import sqlalchemy as sa
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

DB_URL = os.environ["DB_CONNECTION_STRING"]
LI_BASE = os.environ["LOGINSIGHT_BASE_URL"]
LI_TOKEN = os.environ["LOGINSIGHT_API_TOKEN"]
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL")

claude = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — GATHER RAW METRICS
# Collect a broad snapshot of current + baseline data.
# No threshold decisions made here — Claude does that in Step 2.
# ─────────────────────────────────────────────────────────────────────────────

def gather_db_metrics() -> dict:
    """Pull a broad set of DB metrics covering last 1h and 7-day baselines."""
    engine = sa.create_engine(DB_URL, pool_pre_ping=True)
    metrics = {}

    with engine.connect() as conn:

        # ── Failed logins ────────────────────────────────────────────────────
        metrics["failed_logins"] = {
            "last_1h": conn.execute(sa.text("""
                SELECT COUNT(*) FROM login_attempts
                WHERE success = false AND attempted_at >= NOW() - INTERVAL '1 hour'
            """)).scalar(),
            "last_24h": conn.execute(sa.text("""
                SELECT COUNT(*) FROM login_attempts
                WHERE success = false AND attempted_at >= NOW() - INTERVAL '24 hours'
            """)).scalar(),
            "7day_hourly_avg": conn.execute(sa.text("""
                SELECT ROUND(COUNT(*) / 168.0, 1) FROM login_attempts
                WHERE success = false AND attempted_at >= NOW() - INTERVAL '7 days'
            """)).scalar(),
        }

        # ── New user signups ─────────────────────────────────────────────────
        metrics["new_users"] = {
            "last_1h": conn.execute(sa.text("""
                SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL '1 hour'
            """)).scalar(),
            "7day_hourly_avg": conn.execute(sa.text("""
                SELECT ROUND(COUNT(*) / 168.0, 1) FROM users
                WHERE created_at >= NOW() - INTERVAL '7 days'
            """)).scalar(),
        }

        # ── Orders / transactions ────────────────────────────────────────────
        metrics["orders"] = {
            "last_1h": conn.execute(sa.text("""
                SELECT COUNT(*) FROM orders WHERE created_at >= NOW() - INTERVAL '1 hour'
            """)).scalar(),
            "7day_hourly_avg": conn.execute(sa.text("""
                SELECT ROUND(COUNT(*) / 168.0, 1) FROM orders
                WHERE created_at >= NOW() - INTERVAL '7 days'
            """)).scalar(),
        }

        # ── Active DB connections ────────────────────────────────────────────
        metrics["db_connections"] = {
            "current_active": conn.execute(sa.text("""
                SELECT COUNT(*) FROM pg_stat_activity WHERE state = 'active'
            """)).scalar(),
            "current_idle": conn.execute(sa.text("""
                SELECT COUNT(*) FROM pg_stat_activity WHERE state = 'idle'
            """)).scalar(),
        }

        # ── Replication lag ──────────────────────────────────────────────────
        lag = conn.execute(sa.text("""
            SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))::int
        """)).scalar()
        metrics["replication_lag_seconds"] = lag

        # ── Top 5 slowest recent queries ────────────────────────────────────
        slow = conn.execute(sa.text("""
            SELECT LEFT(query, 120) AS query_snippet,
                   ROUND(EXTRACT(EPOCH FROM (now() - query_start))::numeric, 1) AS running_seconds
            FROM pg_stat_activity
            WHERE state = 'active'
              AND now() - query_start > INTERVAL '2 seconds'
              AND query NOT ILIKE '%pg_stat%'
            ORDER BY query_start ASC
            LIMIT 5
        """)).fetchall()
        metrics["slow_queries"] = [
            {"snippet": r[0], "running_seconds": r[1]} for r in slow
        ]

    engine.dispose()
    return metrics


async def gather_loginsight_metrics() -> dict:
    """Pull log counts and a sample of recent events from LoginSight."""
    headers = {"Authorization": f"Bearer {LI_TOKEN}"}
    now = datetime.now(timezone.utc)
    metrics = {}

    async with httpx.AsyncClient(timeout=20) as client:

        # ── Severity counts last 1h ──────────────────────────────────────────
        severity_counts = {}
        for severity in ["CRITICAL", "ERROR", "WARN", "INFO"]:
            window = (now - timedelta(hours=1)).isoformat()
            try:
                r = await client.post(
                    f"{LI_BASE}/api/v1/events/query",
                    headers=headers,
                    json={"filter": f"severity={severity} AND timestamp>={window}", "aggregate": "count"},
                )
                severity_counts[severity] = r.json().get("count", 0) if r.is_success else "error"
            except Exception:
                severity_counts[severity] = "error"
        metrics["severity_counts_last_1h"] = severity_counts

        # ── Severity counts last 7 days (for baseline comparison) ────────────
        severity_counts_7d = {}
        for severity in ["CRITICAL", "ERROR", "WARN"]:
            window = (now - timedelta(days=7)).isoformat()
            try:
                r = await client.post(
                    f"{LI_BASE}/api/v1/events/query",
                    headers=headers,
                    json={"filter": f"severity={severity} AND timestamp>={window}", "aggregate": "count"},
                )
                count_7d = r.json().get("count", 0) if r.is_success else 0
                severity_counts_7d[severity] = {
                    "total_7d": count_7d,
                    "hourly_avg": round(count_7d / 168, 1),
                }
            except Exception:
                severity_counts_7d[severity] = "error"
        metrics["severity_baseline_7d"] = severity_counts_7d

        # ── Unique hosts with errors last 1h ─────────────────────────────────
        try:
            window = (now - timedelta(hours=1)).isoformat()
            r = await client.post(
                f"{LI_BASE}/api/v1/events/query",
                headers=headers,
                json={"filter": f"severity=ERROR AND timestamp>={window}", "aggregate": "count_distinct", "field": "host"},
            )
            metrics["unique_error_hosts_last_1h"] = r.json().get("count", 0) if r.is_success else "error"
        except Exception:
            metrics["unique_error_hosts_last_1h"] = "error"

        # ── Sample of 5 most recent CRITICAL/ERROR events ────────────────────
        try:
            window = (now - timedelta(minutes=30)).isoformat()
            r = await client.post(
                f"{LI_BASE}/api/v1/events/query",
                headers=headers,
                json={
                    "filter": f"severity IN (CRITICAL,ERROR) AND timestamp>={window}",
                    "limit": 5,
                    "order": "desc",
                },
            )
            metrics["recent_critical_error_samples"] = r.json().get("events", []) if r.is_success else []
        except Exception:
            metrics["recent_critical_error_samples"] = []

    return metrics


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — ASK CLAUDE TO INTERPRET
# Pass the raw metrics snapshot to Claude and ask it to reason about anomalies.
# Claude has no hardcoded thresholds — it uses judgement based on the data.
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """
You are an expert data analyst monitoring a production system.
You will receive a JSON snapshot of current database and log metrics,
including current values and 7-day baselines.

Your job:
1. Identify any genuine anomalies — values that deviate meaningfully from baseline
   or patterns that suggest a real problem (not just normal variation)
2. Correlate DB and log anomalies where they overlap in time
3. Assess severity: HIGH (immediate attention), MEDIUM (investigate soon), LOW (monitor)
4. Write a concise plain English report

Respond ONLY with a JSON object in this exact structure — no preamble, no markdown:
{
  "anomalies_found": true or false,
  "overall_severity": "HIGH" | "MEDIUM" | "LOW" | "NONE",
  "summary": "2-3 sentence plain English overview of what you found",
  "findings": [
    {
      "severity": "HIGH" | "MEDIUM" | "LOW",
      "area": "database" | "logs" | "correlated",
      "title": "Short title",
      "detail": "Specific numbers and what they mean",
      "recommended_action": "What to do next"
    }
  ]
}

If nothing is anomalous, set anomalies_found to false, overall_severity to NONE,
findings to [], and write a brief all-clear summary.
"""


def ask_claude_to_interpret(db_metrics: dict, log_metrics: dict) -> dict:
    """Send metrics snapshot to Claude and get back a structured anomaly report."""

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "database_metrics": db_metrics,
        "loginsight_metrics": log_metrics,
    }

    response = claude.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1500,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": (
                    "Here is the current metrics snapshot. "
                    "Identify any anomalies and return your analysis as JSON.\n\n"
                    f"{json.dumps(payload, indent=2, default=str)}"
                ),
            }
        ],
    )

    raw = response.content[0].text.strip()

    # Strip markdown fences if Claude wrapped the JSON
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]

    return json.loads(raw)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — ALERT
# ─────────────────────────────────────────────────────────────────────────────

async def send_slack_report(report: dict):
    if not SLACK_WEBHOOK:
        return

    severity_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "NONE": "✅"}
    emoji = severity_emoji.get(report["overall_severity"], "⚪")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} Anomaly Report — {timestamp}"},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Summary:* {report['summary']}"},
        },
    ]

    for finding in report.get("findings", []):
        fe = severity_emoji.get(finding["severity"], "⚪")
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{fe} *{finding['title']}* ({finding['area']})\n"
                    f"{finding['detail']}\n"
                    f"_Action: {finding['recommended_action']}_"
                ),
            },
        })

    async with httpx.AsyncClient() as client:
        await client.post(SLACK_WEBHOOK, json={"blocks": blocks})

    log.info(f"Slack report sent — severity: {report['overall_severity']}, findings: {len(report.get('findings', []))}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN JOB
# ─────────────────────────────────────────────────────────────────────────────

async def run_ai_anomaly_check():
    log.info("── Running AI anomaly check ──")

    # Gather metrics concurrently
    loop = asyncio.get_event_loop()
    db_task = loop.run_in_executor(None, gather_db_metrics)
    log_task = gather_loginsight_metrics()

    db_metrics, log_metrics = await asyncio.gather(db_task, log_task)

    # Ask Claude to interpret
    report = ask_claude_to_interpret(db_metrics, log_metrics)
    log.info(f"Claude report: severity={report['overall_severity']}, anomalies={report['anomalies_found']}")

    # Only alert if something was found
    if report["anomalies_found"]:
        await send_slack_report(report)
    else:
        log.info(f"All clear: {report['summary']}")

    return report


async def main():
    scheduler = AsyncIOScheduler()

    # Run every 30 minutes — AI calls have a small cost so slightly less frequent than Level 1
    scheduler.add_job(run_ai_anomaly_check, "interval", minutes=30, id="ai_anomaly_check")

    # Also run immediately on startup so you get a baseline report right away
    scheduler.add_job(run_ai_anomaly_check, "date", run_date=datetime.now(), id="startup_check")

    scheduler.start()
    log.info("AI anomaly scheduler started. Checks every 30 minutes. Ctrl+C to stop.")

    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
