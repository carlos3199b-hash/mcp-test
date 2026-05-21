"""
Level 1 — Scheduled Anomaly Checker
====================================
Simple threshold-based anomaly detection that runs on a cron schedule.
Calls your existing MCP tools directly, compares metrics against baselines,
and sends Slack / email alerts when thresholds are breached.

Setup:
  1. pip install apscheduler sqlalchemy httpx python-dotenv

  2. Create a .env file alongside this script:
       DB_CONNECTION_STRING=postgresql://user:pass@replica-host/dbname
       LOGINSIGHT_BASE_URL=https://loginsight.example.com
       LOGINSIGHT_API_TOKEN=your-token-here
       SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz
       ALERT_EMAIL=you@example.com        # optional

  3. Run continuously:
       python level1_anomaly_check.py

  OR add to cron instead of running APScheduler:
       */15 * * * * /usr/bin/python3 /path/to/level1_anomaly_check.py --once
"""

import asyncio
import json
import logging
import os
import smtplib
import sys
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText

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
ALERT_EMAIL = os.environ.get("ALERT_EMAIL")

# ── Thresholds — tune these to your environment ───────────────────────────────
THRESHOLDS = {
    # DB checks
    "error_log_spike_pct": 20,          # alert if errors up >20% vs 7-day avg
    "failed_logins_per_hour": 50,       # alert if failed logins exceed this
    "slow_queries_per_hour": 30,        # alert if slow queries exceed this
    "row_growth_pct_per_hour": 5,       # alert if a table grows >5% in one hour

    # LoginSight checks
    "critical_logs_per_15min": 10,      # alert if CRITICAL logs exceed this
    "error_logs_per_15min": 50,         # alert if ERROR logs exceed this
    "unique_error_hosts_per_hour": 5,   # alert if errors spread to many hosts
}


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE CHECKS
# ─────────────────────────────────────────────────────────────────────────────

def get_engine():
    return sa.create_engine(DB_URL, pool_pre_ping=True)


def check_failed_logins() -> list[dict]:
    """Count failed logins in the last hour vs the 7-day hourly average."""
    engine = get_engine()
    findings = []
    with engine.connect() as conn:
        # Current hour count — adjust table/column names to your schema
        current = conn.execute(sa.text("""
            SELECT COUNT(*) AS cnt
            FROM login_attempts
            WHERE success = false
              AND attempted_at >= NOW() - INTERVAL '1 hour'
        """)).scalar()

        # 7-day hourly average
        baseline = conn.execute(sa.text("""
            SELECT COUNT(*) / 168.0 AS avg_per_hour
            FROM login_attempts
            WHERE success = false
              AND attempted_at >= NOW() - INTERVAL '7 days'
        """)).scalar()

        pct_change = ((current - baseline) / baseline * 100) if baseline else 0

        if current > THRESHOLDS["failed_logins_per_hour"]:
            findings.append({
                "check": "failed_logins",
                "severity": "HIGH" if current > THRESHOLDS["failed_logins_per_hour"] * 2 else "MEDIUM",
                "message": f"Failed logins last hour: {current} (7-day avg: {baseline:.1f}, change: {pct_change:+.1f}%)",
                "value": current,
                "baseline": float(baseline or 0),
            })

    engine.dispose()
    return findings


def check_slow_queries() -> list[dict]:
    """Count slow queries (>1s) in the last hour — PostgreSQL pg_stat_statements."""
    engine = get_engine()
    findings = []
    with engine.connect() as conn:
        try:
            result = conn.execute(sa.text("""
                SELECT COUNT(*) AS slow_count
                FROM pg_stat_activity
                WHERE state = 'active'
                  AND now() - query_start > INTERVAL '1 second'
                  AND query NOT ILIKE '%pg_stat%'
            """)).scalar()

            if result > THRESHOLDS["slow_queries_per_hour"]:
                findings.append({
                    "check": "slow_queries",
                    "severity": "MEDIUM",
                    "message": f"Active slow queries (>1s): {result}",
                    "value": result,
                })
        except Exception as e:
            log.warning(f"slow query check skipped: {e}")

    engine.dispose()
    return findings


def check_table_row_growth(tables: list[str]) -> list[dict]:
    """Alert if any watched table grows unusually fast in the last hour."""
    engine = get_engine()
    findings = []
    with engine.connect() as conn:
        for table in tables:
            try:
                # Approximate count via DB stats (fast, no full scan)
                approx = conn.execute(sa.text(
                    "SELECT reltuples::bigint FROM pg_class WHERE relname = :t"
                ), {"t": table}).scalar() or 0

                # Compare against a simple stored baseline (written each run)
                baseline_key = f"baseline_{table}"
                baseline = _read_baseline(baseline_key)
                _write_baseline(baseline_key, approx)

                if baseline and baseline > 0:
                    pct = (approx - baseline) / baseline * 100
                    if abs(pct) > THRESHOLDS["row_growth_pct_per_hour"]:
                        findings.append({
                            "check": f"row_growth_{table}",
                            "severity": "MEDIUM",
                            "message": f"Table '{table}' row count changed {pct:+.1f}% (was {baseline:,}, now ~{approx:,})",
                            "value": approx,
                            "baseline": baseline,
                        })
            except Exception as e:
                log.warning(f"row growth check for {table} skipped: {e}")

    engine.dispose()
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# LOGINSIGHT CHECKS
# ─────────────────────────────────────────────────────────────────────────────

async def check_loginsight_error_spike() -> list[dict]:
    """Count ERROR and CRITICAL logs in the last 15 minutes."""
    findings = []
    headers = {"Authorization": f"Bearer {LI_TOKEN}"}
    now = datetime.now(timezone.utc)
    window_start = (now - timedelta(minutes=15)).isoformat()

    async with httpx.AsyncClient(timeout=15) as client:
        for severity in ["CRITICAL", "ERROR"]:
            try:
                resp = await client.post(
                    f"{LI_BASE}/api/v1/events/query",
                    headers=headers,
                    json={
                        "filter": f"severity={severity} AND timestamp>={window_start}",
                        "aggregate": "count",
                    },
                )
                resp.raise_for_status()
                count = resp.json().get("count", 0)
                threshold_key = f"{severity.lower()}_logs_per_15min"
                threshold = THRESHOLDS.get(threshold_key, 999)

                if count > threshold:
                    findings.append({
                        "check": f"loginsight_{severity.lower()}_spike",
                        "severity": "HIGH" if severity == "CRITICAL" else "MEDIUM",
                        "message": f"LoginSight {severity} logs last 15min: {count} (threshold: {threshold})",
                        "value": count,
                        "threshold": threshold,
                    })
            except Exception as e:
                log.warning(f"LoginSight {severity} check failed: {e}")

    return findings


async def check_loginsight_host_spread() -> list[dict]:
    """Alert if errors are spreading across many unique hosts (potential incident)."""
    findings = []
    headers = {"Authorization": f"Bearer {LI_TOKEN}"}
    now = datetime.now(timezone.utc)
    window_start = (now - timedelta(hours=1)).isoformat()

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.post(
                f"{LI_BASE}/api/v1/events/query",
                headers=headers,
                json={
                    "filter": f"severity=ERROR AND timestamp>={window_start}",
                    "aggregate": "count_distinct",
                    "field": "host",
                },
            )
            resp.raise_for_status()
            unique_hosts = resp.json().get("count", 0)
            threshold = THRESHOLDS["unique_error_hosts_per_hour"]

            if unique_hosts > threshold:
                findings.append({
                    "check": "loginsight_host_spread",
                    "severity": "HIGH",
                    "message": f"Errors spreading across {unique_hosts} unique hosts in last hour (threshold: {threshold}) — possible widespread incident",
                    "value": unique_hosts,
                    "threshold": threshold,
                })
        except Exception as e:
            log.warning(f"LoginSight host spread check failed: {e}")

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# BASELINE PERSISTENCE (simple JSON file — swap for Redis if you prefer)
# ─────────────────────────────────────────────────────────────────────────────

BASELINE_FILE = "/tmp/anomaly_baselines.json"

def _read_baseline(key: str):
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f).get(key)
    except Exception:
        return None

def _write_baseline(key: str, value):
    try:
        try:
            with open(BASELINE_FILE) as f:
                data = json.load(f)
        except Exception:
            data = {}
        data[key] = value
        with open(BASELINE_FILE, "w") as f:
            json.dump(data, f)
    except Exception as e:
        log.warning(f"Could not write baseline for {key}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# ALERTING
# ─────────────────────────────────────────────────────────────────────────────

async def send_slack_alert(findings: list[dict]):
    if not SLACK_WEBHOOK:
        return
    severity_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
    lines = [f"*Anomaly Report — {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC*\n"]
    for f in findings:
        emoji = severity_emoji.get(f["severity"], "⚪")
        lines.append(f"{emoji} *{f['severity']}* | {f['check']}\n_{f['message']}_\n")

    async with httpx.AsyncClient() as client:
        await client.post(SLACK_WEBHOOK, json={"text": "\n".join(lines)})
    log.info(f"Slack alert sent ({len(findings)} findings)")


def send_email_alert(findings: list[dict]):
    if not ALERT_EMAIL:
        return
    body = "\n\n".join(
        f"[{f['severity']}] {f['check']}\n{f['message']}" for f in findings
    )
    msg = MIMEText(body)
    msg["Subject"] = f"⚠️ Anomaly Alert — {len(findings)} finding(s)"
    msg["From"] = ALERT_EMAIL
    msg["To"] = ALERT_EMAIL
    try:
        with smtplib.SMTP("localhost") as s:   # adjust SMTP host as needed
            s.send_message(msg)
        log.info("Email alert sent")
    except Exception as e:
        log.warning(f"Email send failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCHEDULED JOB
# ─────────────────────────────────────────────────────────────────────────────

# Tables to monitor for unexpected row growth — update to your actual table names
WATCHED_TABLES = ["users", "orders", "login_attempts", "audit_log"]


async def run_all_checks():
    log.info("── Running anomaly checks ──")
    all_findings: list[dict] = []

    # DB checks (sync — run in thread pool to avoid blocking event loop)
    loop = asyncio.get_event_loop()
    all_findings += await loop.run_in_executor(None, check_failed_logins)
    all_findings += await loop.run_in_executor(None, check_slow_queries)
    all_findings += await loop.run_in_executor(None, lambda: check_table_row_growth(WATCHED_TABLES))

    # LoginSight checks (async)
    all_findings += await check_loginsight_error_spike()
    all_findings += await check_loginsight_host_spread()

    if all_findings:
        log.info(f"Found {len(all_findings)} anomalies — sending alerts")
        await send_slack_alert(all_findings)
        send_email_alert(all_findings)
    else:
        log.info("No anomalies found")

    return all_findings


async def main():
    # If called with --once flag (e.g. from cron), run once and exit
    if "--once" in sys.argv:
        await run_all_checks()
        return

    # Otherwise run on a schedule using APScheduler
    scheduler = AsyncIOScheduler()

    # Every 15 minutes — log spike checks
    scheduler.add_job(run_all_checks, "interval", minutes=15, id="15min_checks")

    scheduler.start()
    log.info("Scheduler started. Checks running every 15 minutes. Ctrl+C to stop.")

    try:
        await asyncio.Event().wait()   # run forever
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
