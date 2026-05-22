"""
MCP Server using FastMCP with sqlcmd integration.

Connection defaults (edit as needed):
  SERVER  : your_server_name or your_server\\instance
  DATABASE: your_database_name

Authentication: Windows integrated (-E flag, no username/password required).
Transport     : stdio (compatible with Claude Desktop and VS Code MCP clients).

Install dependencies:
  pip install fastmcp azure-ai-inference

GitHub Copilot AI (natural_language_query tool):
  Set GITHUB_TOKEN to a GitHub Personal Access Token with models:read scope.
  Get one at: https://github.com/settings/tokens
"""

import subprocess
import json
import os
from fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Default connection settings – change these to match your environment
# ---------------------------------------------------------------------------
DEFAULT_SERVER   = r"CSNP00095972.us.ups.com\RR1SHRD01"  # e.g. "MYSERVER" or "MYSERVER\\SQLEXPRESS"
DEFAULT_DATABASE = "D279RMS0" # e.g. "master"
# VmWare LogInsight API defaults
LOGINSIGHT_URL = "https://lmpwwcpeapp3.ups.com:9543"
LOGINSIGHT_USERNAME = "apa_alert"
LOGINSIGHT_PASSWORD = os.getenv("LOGINSIGHT_PASSWORD", "")  # Set this in your environment for security
SQLCMD_PATH      = "sqlcmd"             # full path if not on PATH, e.g. r"C:\Program Files\...\sqlcmd.exe"
# ---------------------------------------------------------------------------

# VmWare LogInsight API query function
import requests

def loginsight_login(url: str, username: str, password: str, provider: str = "Local") -> dict:
    """
    Authenticate to LogInsight via requests and return session id or error.
    """
    login_url = f"{url}/api/v1/sessions"
    try:
        resp = requests.post(
            login_url,
            json={"username": username, "password": password, "provider": provider},
            verify=False,
            timeout=15,
        )
        resp_json = resp.json()
        if resp_json.get("sessionId"):
            return {"sessionId": resp_json["sessionId"], "status_code": resp.status_code, "error": None}
        return {"sessionId": None, "status_code": resp.status_code, "error": str(resp_json)}
    except Exception as e:
        return {"sessionId": None, "status_code": None, "error": str(e)}

def query_loginsight(
    query: str,
    url: str = LOGINSIGHT_URL,
    username: str = LOGINSIGHT_USERNAME,
    password: str = LOGINSIGHT_PASSWORD,
    provider: str = "Local",
    minutes_back: int = 5,
    ts_start_ms: int = None,
    ts_end_ms: int = None,
) -> dict:
    """
    Query the VmWare LogInsight API and return the JSON response.
    Authenticates first to get a session token.

    Args:
        ts_start_ms:  Explicit start timestamp in ms-epoch (overrides minutes_back).
        ts_end_ms:    Explicit end timestamp in ms-epoch (overrides minutes_back).
    """
    login_result = loginsight_login(url, username, password, provider)
    if login_result["error"] or not login_result["sessionId"]:
        return {"json": None, "status_code": login_result["status_code"], "error": f"Login failed: {login_result['error']}"}
    session_id = login_result["sessionId"]

    import time
    if ts_end_ms is None:
        ts_end_ms = int(time.time() * 1000)
    if ts_start_ms is None:
        ts_start_ms = ts_end_ms - (minutes_back * 60 * 1000)

    # LogInsight v2 API: query is encoded in the URL PATH, not as a query parameter
    # Format: /api/v2/events/text/{query}/timestamp/>={start}/timestamp/<={end}?limit=N
    from urllib.parse import quote
    encoded_query = quote(query, safe="")
    api_url = (
        f"{url}/api/v2/events/text/{encoded_query}"
        f"/timestamp/%3E%3D{ts_start_ms}"
        f"/timestamp/%3C%3D{ts_end_ms}"
        f"?limit=1000"
    )
    headers = {"Authorization": f"Bearer {session_id}"}
    try:
        resp = requests.get(api_url, headers=headers, verify=False)
        resp_text = resp.text.strip()
        if not resp_text:
            return {"json": None, "status_code": resp.status_code, "error": f"Empty response (HTTP {resp.status_code})"}
        resp_json = resp.json()
        error_msg = resp_json.get("errorMessage") if "errorMessage" in resp_json else None
        if error_msg:
            error_msg = f"{error_msg} | URL: {resp.url}"
        return {"json": resp_json, "status_code": resp.status_code, "error": error_msg}
    except Exception as e:
        return {"json": None, "status_code": None, "error": str(e)}


def fetch_events_with_token(
    session_id: str,
    query: str,
    url: str,
    ts_start_ms: int,
    ts_end_ms: int,
) -> dict:
    """
    Fetch up to 1,000 events using an existing LogInsight session token.
    Avoids re-authenticating on every paginated request.
    """
    from urllib.parse import quote
    encoded_query = quote(query, safe="")
    api_url = (
        f"{url}/api/v2/events/text/{encoded_query}"
        f"/timestamp/%3E%3D{ts_start_ms}"
        f"/timestamp/%3C%3D{ts_end_ms}"
        f"?limit=1000"
    )
    headers = {"Authorization": f"Bearer {session_id}"}
    try:
        resp = requests.get(api_url, headers=headers, verify=False)
        resp_text = resp.text.strip()
        if not resp_text:
            return {"json": None, "error": f"Empty response (HTTP {resp.status_code})"}
        resp_json = resp.json()
        error_msg = resp_json.get("errorMessage")
        return {"json": resp_json, "error": error_msg}
    except Exception as e:
        return {"json": None, "error": str(e)}


mcp = FastMCP("retail-server")


def run_sqlcmd(
    query: str,
    server: str = DEFAULT_SERVER,
    database: str = DEFAULT_DATABASE,
) -> dict:
    """
    Execute a T-SQL query via sqlcmd (Windows integrated auth) and return
    the output as a dict with keys 'stdout', 'stderr', and 'returncode'.
    """
    cmd = [
        SQLCMD_PATH,
        "-S", server,
        "-d", database,
        "-E",           # Windows integrated authentication (NTLM/Kerberos)
        "-Q", query,
        "-s", ",",      # column separator (CSV-friendly)
        "-W",           # remove trailing spaces
        "-h", "-1",     # no column headers repetition (use -1 to suppress header)
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )

    return {
        "stdout":     result.stdout.strip(),
        "stderr":     result.stderr.strip(),
        "returncode": result.returncode,
    }


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------

# VmWare LogInsight MCP tool
@mcp.tool()
def loginsight_query(
    query: str,
    url: str = LOGINSIGHT_URL,
    username: str = LOGINSIGHT_USERNAME,
    password: str = LOGINSIGHT_PASSWORD,
    minutes_back: int = 5,
) -> str:
    """
    Run a query against the VmWare LogInsight API.
    Args:
        query:        The LogInsight query string (LIQL/text search).
        url:          LogInsight API endpoint.
        username:     LogInsight username.
        password:     LogInsight password (set LOGINSIGHT_PASSWORD env var).
        minutes_back: How far back in time to search (default: 5 minutes).
    Returns:
        Query output as a string, or an error message.
    """
    result = query_loginsight(query, url, username, password, minutes_back=minutes_back)
    if result["error"]:
        return f"ERROR: {result['error']}"
    return json.dumps(result["json"], indent=2) if result["json"] else f"No data returned (status {result['status_code']})"


@mcp.tool()
def get_api_response_times(
    minutes_back: int = 60,
    offset_minutes: int = 0,
    api_filter: str = None,
    url: str = LOGINSIGHT_URL,
    username: str = LOGINSIGHT_USERNAME,
    password: str = LOGINSIGHT_PASSWORD,
) -> str:
    """
    Fetch RMS application RPT|O logs from LogInsight and return a pre-aggregated
    summary of API response times. Safe for all MCP hosts (VS Code, M365, etc.)
    as it always returns a small JSON summary regardless of log volume.

    Uses time-sliced pagination to work around the LogInsight 1,000-event cap —
    each hour is fetched as a separate request so high-volume windows are accurate.

    Args:
        minutes_back:    How far back to analyse (default: 60). Use 360 for 6h, 1440 for 24h.
        offset_minutes:  Shift the entire window back by this many minutes (default: 0 = now).
                         Use 1440 to query the same window from 24 hours ago.
        api_filter:      Optional API name to restrict results, e.g. "ViewAccessPoint".
        url:             LogInsight API endpoint.
        username:        LogInsight username.
        password:        LogInsight password.

    Returns:
        JSON string with per-API stats: call_count, avg_ms, p50_ms, p95_ms, max_ms, error_count.
        Also includes a "sampled" flag per time-slice if the 1,000-event cap was hit.
    """
    import re as _re
    from collections import defaultdict

    # --- Field positions in pipe-delimited RMS RPT|O log lines ---
    # timestamp|server|thread|client_type|user|session|level|class|method|RPT|O|
    # API_NAME|...|status|error_code|RESPONSE_MS|...
    API_IDX    = 11
    STATUS_IDX = 20
    MS_IDX     = 22
    AP_IDX     = 15

    api_times       = defaultdict(list)
    api_errors      = defaultdict(int)
    api_error_codes = defaultdict(lambda: defaultdict(int))
    ap_calls        = defaultdict(int)
    slices_hit_cap = []

    # Time-slice into 1h windows to stay under the 1,000-event cap per request
    slice_minutes = 60
    total_slices  = max(1, (minutes_back + slice_minutes - 1) // slice_minutes)

    import time as _time
    now_ms    = int(_time.time() * 1000) - (offset_minutes * 60 * 1000)
    start_ms  = now_ms - (minutes_back * 60 * 1000)

    for s in range(total_slices):
        slice_start = start_ms + s * slice_minutes * 60 * 1000
        slice_end   = min(slice_start + slice_minutes * 60 * 1000, now_ms)

        # Login ONCE per slice — reuse the token for all paginated page fetches
        login_result = loginsight_login(url, username, password)
        if login_result["error"] or not login_result["sessionId"]:
            continue
        session_id = login_result["sessionId"]

        # Paginate through all events in this slice using timestamp walk-back.
        # LogInsight returns events newest-first; when we hit the 1,000-event cap,
        # we use the oldest event's timestamp as the next window's upper bound.
        # max_pages caps total requests per slice to keep response time reasonable
        # (10 pages = 10,000 events, ample for accurate percentile calculation).
        window_end = slice_end
        slice_total = 0
        max_pages = 3
        pages_fetched = 0
        while pages_fetched < max_pages:
            raw = fetch_events_with_token(
                session_id, "logServiceAction", url,
                ts_start_ms=slice_start,
                ts_end_ms=window_end,
            )
            if raw["error"] or not raw["json"]:
                break

            events = raw["json"].get("events", [])
            if not events:
                break
            slice_total += len(events)
            pages_fetched += 1

            for e in events:
                txt = e.get("text", "")
                if "RPT|O" not in txt:
                    continue
                m = _re.search(r'\] (.+)', txt)
                if not m:
                    continue
                parts = m.group(1).split("|")
                if len(parts) <= MS_IDX:
                    continue
                api      = parts[API_IDX].strip()
                status   = parts[STATUS_IDX].strip()
                err_code = parts[21].strip() if len(parts) > 21 else ""
                ap_id    = parts[AP_IDX].strip() if len(parts) > AP_IDX else ""
                try:
                    ms = int(parts[MS_IDX].strip())
                except ValueError:
                    continue
                if api_filter and api != api_filter:
                    continue
                api_times[api].append(ms)
                if ap_id and ap_id not in ("null", ""):
                    ap_calls[ap_id] += 1
                if status != "SUCCESS":
                    api_errors[api] += 1
                    api_error_codes[api][err_code or "(blank)"] += 1

            # If we got a full page, walk back to just before the oldest event
            if len(events) < 1000:
                break  # last page — done
            oldest_ts = min(e.get("timestamp", slice_start) for e in events)
            if oldest_ts <= slice_start:
                break  # can't go further back
            window_end = oldest_ts - 1

        if slice_total >= 1000:
            slices_hit_cap.append(s)

    # --- Build summary ---
    summary = []
    for api, times in sorted(api_times.items()):
        ts = sorted(times)
        n  = len(ts)
        entry = {
            "api":            api,
            "call_count":     n,
            "avg_ms":         round(sum(ts) / n),
            "p50_ms":         ts[int(n * 0.50)],
            "p95_ms":         ts[min(int(n * 0.95), n - 1)],
            "max_ms":         ts[-1],
            "error_count":    api_errors[api],
            "error_rate_pct": round(api_errors[api] / n * 100, 1),
        }
        if api_error_codes[api]:
            top_codes = sorted(api_error_codes[api].items(), key=lambda x: -x[1])
            entry["error_codes"] = {code: cnt for code, cnt in top_codes[:10]}
        summary.append(entry)

    # Sort by avg_ms descending
    summary.sort(key=lambda x: -x["avg_ms"])

    all_times = [t for v in api_times.values() for t in v]
    overall   = {}
    if all_times:
        at = sorted(all_times)
        n  = len(at)
        overall = {
            "call_count":  n,
            "avg_ms":      round(sum(at) / n),
            "p50_ms":      at[int(n * 0.50)],
            "p95_ms":      at[min(int(n * 0.95), n - 1)],
            "max_ms":      at[-1],
            "error_count": sum(api_errors.values()),
        }

    # --- Top Access Points ---
    top_aps = [
        {"ap_id": ap_id, "call_count": cnt}
        for ap_id, cnt in sorted(ap_calls.items(), key=lambda x: -x[1])[:10]
    ]

    return json.dumps({
        "window_minutes":    minutes_back,
        "slices_queried":    total_slices,
        "slices_hit_cap":    slices_hit_cap,
        "overall":           overall,
        "apis":              summary,
        "top_access_points": top_aps,
    }, indent=2)


@mcp.tool()
def execute_query(
    query: str,
    server: str = DEFAULT_SERVER,
    database: str = DEFAULT_DATABASE,
) -> str:
    """
    Run a T-SQL query against a SQL Server using sqlcmd (Windows auth).

    Args:
        query:    The T-SQL statement to execute.
        server:   SQL Server hostname or instance (default: DEFAULT_SERVER).
        database: Target database name (default: DEFAULT_DATABASE).

    Returns:
        Query output as a string, or an error message.
    """
    result = run_sqlcmd(query, server, database)

    if result["returncode"] != 0:
        return f"ERROR (exit {result['returncode']}):\n{result['stderr'] or result['stdout']}"

    return result["stdout"] if result["stdout"] else "(no rows returned)"


@mcp.tool()
def list_tables(
    server: str = DEFAULT_SERVER,
    database: str = DEFAULT_DATABASE,
) -> str:
    """
    Return a list of user tables in the target database.

    Args:
        server:   SQL Server hostname or instance.
        database: Target database name.

    Returns:
        Comma-separated output of table names.
    """
    query = "SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_SCHEMA, TABLE_NAME;"
    return execute_query(query, server, database)


@mcp.tool()
def get_row_count(
    table: str,
    server: str = DEFAULT_SERVER,
    database: str = DEFAULT_DATABASE,
) -> str:
    """
    Return the approximate row count for a given table.

    Args:
        table:    Table name (optionally schema-qualified, e.g. 'dbo.MyTable').
        server:   SQL Server hostname or instance.
        database: Target database name.

    Returns:
        Row count as a string.
    """
    # Validate table name to prevent SQL injection (only allow word chars, dots, brackets)
    import re
    if not re.fullmatch(r"[\w\.\[\]]+", table):
        return "ERROR: Invalid table name."

    query = f"SELECT COUNT(*) AS row_count FROM {table};"
    return execute_query(query, server, database)


@mcp.tool()
def natural_language_query(
    question: str,
    server: str = DEFAULT_SERVER,
    database: str = DEFAULT_DATABASE,
) -> str:
    """
    Ask a question in plain English. GitHub Copilot AI translates it to T-SQL,
    which is then executed against the database.

    Requires GITHUB_TOKEN environment variable (Personal Access Token with
    models:read scope). Create one at https://github.com/settings/tokens

    Args:
        question: Plain-English question, e.g. "How many devices are in each state?"
        server:   SQL Server hostname or instance.
        database: Target database name.

    Returns:
        The generated SQL and its results, or an error message.
    """
    try:
        from azure.ai.inference import ChatCompletionsClient
        from azure.ai.inference.models import SystemMessage, UserMessage
        from azure.core.credentials import AzureKeyCredential
    except ImportError:
        return "ERROR: azure-ai-inference package not installed. Run: pip install azure-ai-inference"

    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        return (
            "ERROR: GITHUB_TOKEN environment variable not set.\n"
            "Create a Personal Access Token with models:read scope at "
            "https://github.com/settings/tokens and set it as GITHUB_TOKEN."
        )

    # ------------------------------------------------------------------
    # Step 1: fetch schema so Copilot knows what tables/columns exist
    # ------------------------------------------------------------------
    schema_sql = """
        SELECT
            t.TABLE_SCHEMA + '.' + t.TABLE_NAME AS table_name,
            c.COLUMN_NAME,
            c.DATA_TYPE
        FROM INFORMATION_SCHEMA.TABLES t
        JOIN INFORMATION_SCHEMA.COLUMNS c
            ON c.TABLE_SCHEMA = t.TABLE_SCHEMA
           AND c.TABLE_NAME   = t.TABLE_NAME
        WHERE t.TABLE_TYPE = 'BASE TABLE'
        ORDER BY table_name, c.ORDINAL_POSITION;
    """
    schema_result = run_sqlcmd(schema_sql, server, database)
    if schema_result["returncode"] != 0:
        return f"ERROR fetching schema: {schema_result['stderr'] or schema_result['stdout']}"

    # ------------------------------------------------------------------
    # Step 2: ask GitHub Copilot to translate the question to T-SQL
    # ------------------------------------------------------------------
    client = ChatCompletionsClient(
        endpoint="https://models.inference.ai.azure.com",
        credential=AzureKeyCredential(github_token),
    )

    system_prompt = (
        "You are a T-SQL expert. Given a database schema and a plain-English question, "
        "return ONLY the T-SQL SELECT statement that answers the question. "
        "Do not include explanations, markdown fences, or any text other than the SQL."
    )
    user_prompt = (
        f"Database: {database}\n\n"
        f"Schema (table.column, data_type):\n{schema_result['stdout']}\n\n"
        f"Question: {question}\n\n"
        "T-SQL:"
    )

    try:
        response = client.complete(
            model=os.getenv("GITHUB_COPILOT_MODEL", "gpt-4o"),
            messages=[
                SystemMessage(content=system_prompt),
                UserMessage(content=user_prompt),
            ],
            temperature=0,
        )
        sql = response.choices[0].message.content.strip()
    except Exception as exc:
        return f"ERROR calling GitHub Models AI: {exc}"

    # ------------------------------------------------------------------
    # Step 3: execute the generated SQL
    # ------------------------------------------------------------------
    results = execute_query(sql, server, database)
    return f"Generated SQL:\n{sql}\n\nResults:\n{results}"

# ─────────────────────────────────────────────────────────────────────────────
# TOOL — SQL schema introspection
# Returns table names, columns, types, PKs, FKs, and row counts so Copilot
# understands relationships without you explaining them each session.
# ─────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def get_database_schema(
    include_tables: list[str] | None = None,
    include_row_counts: bool = False,
    server: str = DEFAULT_SERVER,
    database: str = DEFAULT_DATABASE,
) -> str:
    """
    Introspect the SQL Server database and return full schema context:
    table definitions, column types, primary keys, foreign keys, and indexes.

    Args:
        include_tables:    Optional list of table names to limit output.
                           If None, all tables are returned.
        include_row_counts: If True, also fetch approximate row counts via
                            sys.partitions (SQL Server; no full table scan).
        server:            SQL Server hostname or instance.
        database:          Target database name.
    Returns:
        JSON string describing the schema, ready for Copilot to parse.
    """
    # ------------------------------------------------------------------
    # Columns
    # ------------------------------------------------------------------
    col_sql = """
        SELECT
            t.TABLE_SCHEMA + '.' + t.TABLE_NAME AS table_name,
            c.COLUMN_NAME,
            c.DATA_TYPE,
            c.IS_NULLABLE,
            c.COLUMN_DEFAULT
        FROM INFORMATION_SCHEMA.TABLES t
        JOIN INFORMATION_SCHEMA.COLUMNS c
            ON c.TABLE_SCHEMA = t.TABLE_SCHEMA
           AND c.TABLE_NAME   = t.TABLE_NAME
        WHERE t.TABLE_TYPE = 'BASE TABLE'
        ORDER BY table_name, c.ORDINAL_POSITION;
    """
    col_result = run_sqlcmd(col_sql, server, database)
    if col_result["returncode"] != 0:
        return f"ERROR fetching columns: {col_result['stderr'] or col_result['stdout']}"

    # ------------------------------------------------------------------
    # Primary keys
    # ------------------------------------------------------------------
    pk_sql = """
        SELECT
            tc.TABLE_SCHEMA + '.' + tc.TABLE_NAME AS table_name,
            kcu.COLUMN_NAME
        FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
        JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu
            ON kcu.CONSTRAINT_NAME = tc.CONSTRAINT_NAME
           AND kcu.TABLE_SCHEMA    = tc.TABLE_SCHEMA
           AND kcu.TABLE_NAME      = tc.TABLE_NAME
        WHERE tc.CONSTRAINT_TYPE = 'PRIMARY KEY'
        ORDER BY table_name, kcu.ORDINAL_POSITION;
    """
    pk_result = run_sqlcmd(pk_sql, server, database)

    # ------------------------------------------------------------------
    # Foreign keys
    # ------------------------------------------------------------------
    fk_sql = """
        SELECT
            fk.TABLE_SCHEMA + '.' + fk.TABLE_NAME  AS table_name,
            fk.COLUMN_NAME                          AS local_column,
            pk.TABLE_SCHEMA + '.' + pk.TABLE_NAME  AS referred_table,
            pk.COLUMN_NAME                          AS referred_column
        FROM INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS rc
        JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE fk
            ON fk.CONSTRAINT_NAME = rc.CONSTRAINT_NAME
        JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE pk
            ON pk.CONSTRAINT_NAME = rc.UNIQUE_CONSTRAINT_NAME
           AND pk.ORDINAL_POSITION = fk.ORDINAL_POSITION
        ORDER BY table_name;
    """
    fk_result = run_sqlcmd(fk_sql, server, database)

    # ------------------------------------------------------------------
    # Parse CSV output into a structured dict
    # ------------------------------------------------------------------
    def parse_csv(text: str) -> list[list[str]]:
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("---"):
                rows.append([c.strip() for c in line.split(",")])
        return rows

    schema: dict = {}

    for row in parse_csv(col_result["stdout"]):
        if len(row) < 5:
            continue
        tbl, col_name, dtype, nullable, default = row[0], row[1], row[2], row[3], row[4]
        if include_tables and tbl not in include_tables:
            continue
        schema.setdefault(tbl, {"columns": [], "primary_keys": [], "foreign_keys": []})
        schema[tbl]["columns"].append({
            "name": col_name,
            "type": dtype,
            "nullable": nullable == "YES",
            "default": default,
        })

    for row in parse_csv(pk_result["stdout"]):
        if len(row) < 2:
            continue
        tbl, col_name = row[0], row[1]
        if tbl in schema:
            schema[tbl]["primary_keys"].append(col_name)

    for row in parse_csv(fk_result["stdout"]):
        if len(row) < 4:
            continue
        tbl, local_col, ref_tbl, ref_col = row[0], row[1], row[2], row[3]
        if tbl in schema:
            schema[tbl]["foreign_keys"].append({
                "local_column": local_col,
                "refers_to_table": ref_tbl,
                "refers_to_column": ref_col,
            })

    # ------------------------------------------------------------------
    # Optional: approximate row counts (SQL Server sys.partitions)
    # ------------------------------------------------------------------
    if include_row_counts:
        rc_sql = """
            SELECT
                s.name + '.' + t.name AS table_name,
                SUM(p.rows) AS approx_row_count
            FROM sys.tables t
            JOIN sys.schemas s ON s.schema_id = t.schema_id
            JOIN sys.partitions p ON p.object_id = t.object_id AND p.index_id < 2
            GROUP BY s.name, t.name
            ORDER BY table_name;
        """
        rc_result = run_sqlcmd(rc_sql, server, database)
        for row in parse_csv(rc_result["stdout"]):
            if len(row) < 2:
                continue
            tbl, count = row[0], row[1]
            if tbl in schema:
                schema[tbl]["approx_row_count"] = int(count) if count.isdigit() else count

    return json.dumps(schema, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL — LogInsight log field introspection
# Returns known field definitions and a sample of recent events so Copilot
# understands the log structure without you explaining it each session.
# ─────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def get_loginsight_schema(
    sample_size: int = 5,
    url: str = LOGINSIGHT_URL,
    username: str = LOGINSIGHT_USERNAME,
    minutes_back: int = 60,
    max_fields: int = 100,
) -> str:
    """
    Introspect LogInsight to return:
    - All defined field names and types (via /api/v1/fields)
    - A small sample of recent events for pattern recognition

    Args:
        sample_size:  Number of recent events to return as examples (default 5).
        url:          LogInsight API endpoint.
        username:     LogInsight username.
        minutes_back: How far back to pull sample events (default 60 minutes).
        max_fields:   Maximum number of fields to return (default 100). Use 0 for all.
    Returns:
        JSON string describing log fields and sample events.
    """
    password = os.getenv("LOGINSIGHT_PASSWORD", "")

    # ------------------------------------------------------------------
    # Step 1: Authenticate
    # ------------------------------------------------------------------
    login_result = loginsight_login(url, username, password)
    if login_result["error"] or not login_result["sessionId"]:
        return f"ERROR: Login failed: {login_result['error']}"
    session_id = login_result["sessionId"]
    headers = {"Authorization": f"Bearer {session_id}"}

    schema: dict = {}

    # ------------------------------------------------------------------
    # Step 2: Fetch field definitions
    # ------------------------------------------------------------------
    try:
        fields_resp = requests.get(
            f"{url}/api/v1/fields",
            headers=headers,
            verify=False,
            timeout=15,
        )
        if fields_resp.ok:
            raw = fields_resp.json()
            fields_data = raw if isinstance(raw, list) else raw.get("fields", [])
            all_fields = [
                {
                    "name": f.get("name"),
                    "type": f.get("type"),
                    "display_name": f.get("displayName", ""),
                }
                for f in fields_data
            ]
            schema["total_field_count"] = len(all_fields)
            schema["fields"] = all_fields if max_fields == 0 else all_fields[:max_fields]
            if max_fields and len(all_fields) > max_fields:
                schema["fields_truncated"] = True
        else:
            schema["fields"] = f"ERROR fetching fields (HTTP {fields_resp.status_code})"
    except Exception as e:
        schema["fields"] = f"ERROR: {e}"

    # ------------------------------------------------------------------
    # Step 3: Fetch sample recent events (wildcard query)
    # ------------------------------------------------------------------
    import time
    ts_end = int(time.time() * 1000)
    ts_start = ts_end - (minutes_back * 60 * 1000)

    from urllib.parse import quote
    api_url = (
        f"{url}/api/v2/events/text/%2A"        # %2A = * (match all)
        f"/timestamp/%3E%3D{ts_start}"
        f"/timestamp/%3C%3D{ts_end}"
        f"?limit={sample_size}"
    )
    try:
        events_resp = requests.get(api_url, headers=headers, verify=False, timeout=15)
        if events_resp.ok:
            events_data = events_resp.json().get("events", [])
            schema["sample_events"] = events_data
            # Derive observed field names from event keys
            observed_fields: set = set()
            for event in events_data:
                observed_fields.update(event.keys())
            schema["observed_event_keys"] = sorted(observed_fields)
        else:
            schema["sample_events"] = f"ERROR fetching events (HTTP {events_resp.status_code})"
    except Exception as e:
        schema["sample_events"] = f"ERROR: {e}"

    return json.dumps(schema, indent=2)

# ─────────────────────────────────────────────────────────────────────────────
# TOOL 3 — Combined bootstrap (call this once at session start)
# Returns both DB schema and LoginSight patterns in a single tool call,
# minimising round-trips when Copilot initialises the session.
# ─────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def get_full_context() -> str:
    """
    Bootstrap tool — call once at the start of a session.
    Returns a compact database schema (table + column names only) AND
    LogInsight field names combined, so Copilot has full context in a
    single round-trip without exceeding chat size limits.
    """
    # Compact DB schema: table + column names + data type only (no PK/FK/defaults)
    col_sql = """
        SELECT
            t.TABLE_SCHEMA + '.' + t.TABLE_NAME AS table_name,
            c.COLUMN_NAME,
            c.DATA_TYPE
        FROM INFORMATION_SCHEMA.TABLES t
        JOIN INFORMATION_SCHEMA.COLUMNS c
            ON c.TABLE_SCHEMA = t.TABLE_SCHEMA
           AND c.TABLE_NAME   = t.TABLE_NAME
        WHERE t.TABLE_TYPE = 'BASE TABLE'
        ORDER BY table_name, c.ORDINAL_POSITION;
    """
    col_result = run_sqlcmd(col_sql)
    db_tables: dict = {}
    for line in col_result["stdout"].splitlines():
        line = line.strip()
        if not line or line.startswith("---"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            continue
        tbl, col_name, dtype = parts[0], parts[1], parts[2]
        db_tables.setdefault(tbl, []).append(f"{col_name} ({dtype})")

    # Compact LogInsight: field display_names only, no sample events, max 200 fields
    password = os.getenv("LOGINSIGHT_PASSWORD", "")
    login_result = loginsight_login(LOGINSIGHT_URL, LOGINSIGHT_USERNAME, password)
    li_fields: list = []
    li_error: str = ""
    if login_result["sessionId"]:
        try:
            resp = requests.get(
                f"{LOGINSIGHT_URL}/api/v1/fields",
                headers={"Authorization": f"Bearer {login_result['sessionId']}"},
                verify=False,
                timeout=15,
            )
            if resp.ok:
                raw = resp.json()
                fields_data = raw if isinstance(raw, list) else raw.get("fields", [])
                li_fields = [f.get("displayName") or f.get("name") for f in fields_data[:200]]
        except Exception as e:
            li_error = str(e)
    else:
        li_error = login_result["error"]

    result = {
        "database_schema": db_tables,
        "loginsight_fields": li_fields,
        "loginsight_error": li_error or None,
        "instructions": (
            "Use database_schema to understand table relationships and write accurate SQL. "
            "Use loginsight_fields to know available filter/search fields when querying logs."
        ),
    }
    return json.dumps(result, indent=2)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
# Usage:
#   python retail_mcp.py          -> stdio mode  (VS Code / Claude Desktop)
#   python retail_mcp.py --http   -> HTTP mode   (M365 Agent / Copilot Studio)
#                                    Endpoint: http://localhost:8000/mcp
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--http", action="store_true",
                        help="Run as HTTP server for M365 Agent (default: stdio)")
    parser.add_argument("--port", type=int, default=8000,
                        help="Port for HTTP server (default: 8000)")
    args = parser.parse_args()

    if args.http:
        # Use uvicorn directly with ws="none" to avoid the websockets package
        # requirement on Python 3.14 (no pre-built wheel available yet).
        import uvicorn
        http_app = mcp.http_app(transport="streamable-http")
        uvicorn.run(http_app, host="0.0.0.0", port=args.port, ws="none")
    else:
        # stdio mode: used by VS Code and Claude Desktop via mcp.json
        mcp.run(transport="stdio")
