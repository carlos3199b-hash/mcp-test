
# test_mcp_latest.py
#
# Example script to interact with an MCP (Model Context Protocol) server over HTTP.
# Demonstrates session management, tool discovery, and running queries via MCP tools.

import requests, json

# MCP server endpoint
URL = "http://localhost:8000/mcp"
# Standard headers for MCP JSON-RPC
HDR = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
# Session ID for MCP session management
SID = None


def call(method, params=None, id=1, notification=False):
    """
    Send a JSON-RPC request or notification to the MCP server.
    If notification=True, sends as a notification (no id field).
    Handles session ID automatically.
    Prints the HTTP status and first 1000 chars of the response.
    """
    global SID
    # Add session ID header if available
    h = {**HDR, **({"Mcp-Session-Id": SID} if SID else {})}
    # Build JSON-RPC payload
    payload = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    if not notification:
        payload["id"] = id
    # Send the request
    r = requests.post(URL, headers=h, json=payload)
    # Update session ID from response header
    SID = r.headers.get("mcp-session-id", SID)
    print(f"\n[{method}] {r.status_code}")
    print(r.text[:1000])
    return r


# Initialize MCP session (required)
call("initialize", {"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}})
# Notify server that initialization is complete (send as notification)
call("notifications/initialized", notification=True)
# List available MCP tools
call("tools/list", id=2)

# --- Natural language query (requires GITHUB_TOKEN env var) ---
# Example: ask a plain-English question (uncomment to use)
#call("tools/call", {"name":"natural_language_query","arguments":{"question":"How many devices are in each state?"}}, id=3)

# --- Raw T-SQL query ---
# Example: run a direct SQL query via the MCP server
call("tools/call", {"name":"execute_query","arguments":{"query":"SELECT TOP 5 * FROM APD_RMS.TPKG_ACY"}}, id=4)
