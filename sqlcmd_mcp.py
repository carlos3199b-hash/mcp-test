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
from requests.auth import HTTPBasicAuth

def loginsight_login(url: str, username: str, password: str, provider: str = "Local") -> dict:
    """
    Authenticate to LogInsight using curl (matches Perl/shell approach) and return session id or error.
    """
    login_url = f"{url}/api/v1/sessions"
    body = json.dumps({"username": username, "password": password, "provider": provider})
    cmd = ["curl", "-k", "-s", "-X", "POST", login_url, "-d", body]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        resp_text = result.stdout.strip()
        resp_json = json.loads(resp_text) if resp_text else {}
        if resp_json.get("sessionId"):
            return {"sessionId": resp_json["sessionId"], "status_code": 200, "error": None}
        return {"sessionId": None, "status_code": None, "error": resp_text or result.stderr.strip()}
    except Exception as e:
        return {"sessionId": None, "status_code": None, "error": str(e)}

def query_loginsight(
    query: str,
    url: str = LOGINSIGHT_URL,
    username: str = LOGINSIGHT_USERNAME,
    password: str = LOGINSIGHT_PASSWORD,
    provider: str = "Local",
    minutes_back: int = 5,
) -> dict:
    """
    Query the VmWare LogInsight API and return the JSON response.
    Authenticates first to get a session token.
    """
    login_result = loginsight_login(url, username, password, provider)
    if login_result["error"] or not login_result["sessionId"]:
        return {"json": None, "status_code": login_result["status_code"], "error": f"Login failed: {login_result['error']}"}
    session_id = login_result["sessionId"]

    import time
    ts_end = int(time.time() * 1000)
    ts_start = ts_end - (minutes_back * 60 * 1000)

    # LogInsight v2 API: query is encoded in the URL PATH, not as a query parameter
    # Format: /api/v2/events/text/{query}/timestamp/>={start}/timestamp/<={end}?limit=N
    from urllib.parse import quote
    encoded_query = quote(query, safe="")
    api_url = (
        f"{url}/api/v2/events/text/{encoded_query}"
        f"/timestamp/%3E%3D{ts_start}"
        f"/timestamp/%3C%3D{ts_end}"
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


mcp = FastMCP("sqlcmd-server")


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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
# Usage:
#   python sqlcmd_mcp.py          -> stdio mode  (VS Code / Claude Desktop)
#   python sqlcmd_mcp.py --http   -> HTTP mode   (M365 Agent / Copilot Studio)
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
