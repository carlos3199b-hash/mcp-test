"""
MCP Schema Introspection Tool
Add these tools to your existing Python MCP server.
They allow Copilot to bootstrap table relationships and
LoginSight log patterns at the start of each session.
"""

import json
from mcp.server import Server
from mcp.types import Tool, TextContent
import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect


# ── Attach to your existing MCP server instance ──────────────────────────────
server = Server("production-mcp")


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 1 — SQL schema introspection
# Returns table names, columns, types, PKs, FKs, and any doc comments
# so Copilot understands relationships without you explaining them each session.
# ─────────────────────────────────────────────────────────────────────────────
@server.tool()
async def get_database_schema(
    include_tables: list[str] | None = None,
    include_row_counts: bool = False,
) -> str:
    """
    Introspect the production SQL database and return full schema context:
    table definitions, column types, primary keys, foreign keys, and indexes.

    Args:
        include_tables: Optional list of table names to limit output.
                        If None, all tables are returned.
        include_row_counts: If True, also fetch approximate row counts
                            (may be slow on large databases).
    Returns:
        JSON string describing the schema, ready for Copilot to parse.
    """
    engine = sa.create_engine("YOUR_DB_CONNECTION_STRING")  # replace or inject via env
    inspector = sa_inspect(engine)

    all_tables = inspector.get_table_names()
    target_tables = include_tables if include_tables else all_tables

    schema: dict = {}

    for table in target_tables:
        columns = inspector.get_columns(table)
        pk = inspector.get_pk_constraint(table)
        fks = inspector.get_foreign_keys(table)
        indexes = inspector.get_indexes(table)

        schema[table] = {
            "columns": [
                {
                    "name": col["name"],
                    "type": str(col["type"]),
                    "nullable": col.get("nullable", True),
                    "default": str(col.get("default", "")),
                    "comment": col.get("comment", ""),   # picks up DB-level column comments
                }
                for col in columns
            ],
            "primary_keys": pk.get("constrained_columns", []),
            "foreign_keys": [
                {
                    "local_columns": fk["constrained_columns"],
                    "refers_to_table": fk["referred_table"],
                    "refers_to_columns": fk["referred_columns"],
                }
                for fk in fks
            ],
            "indexes": [
                {
                    "name": idx["name"],
                    "columns": idx["column_names"],
                    "unique": idx.get("unique", False),
                }
                for idx in indexes
            ],
        }

        # Optional: approximate row count using DB stats (avoids full scan)
        if include_row_counts:
            with engine.connect() as conn:
                result = conn.execute(
                    sa.text(
                        f"SELECT reltuples::bigint FROM pg_class WHERE relname = :t"  # PostgreSQL
                        # For SQL Server: "SELECT SUM(rows) FROM sys.partitions WHERE object_id=OBJECT_ID(:t) AND index_id<2"
                        # For MySQL:      "SELECT TABLE_ROWS FROM information_schema.TABLES WHERE TABLE_NAME=:t"
                    ),
                    {"t": table},
                )
                row = result.fetchone()
                schema[table]["approx_row_count"] = row[0] if row else "unknown"

    engine.dispose()
    return json.dumps(schema, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 2 — LoginSight log pattern introspection
# Returns known log sources, field names, severity levels, and sample events
# so Copilot knows what to look for when you ask about anomalies.
# ─────────────────────────────────────────────────────────────────────────────
@server.tool()
async def get_loginsight_schema(
    sample_events_per_source: int = 3,
) -> str:
    """
    Introspect LoginSight to return:
    - Available log sources / namespaces
    - Common fields per source (timestamp, severity, host, message, etc.)
    - Distinct severity levels observed
    - A small sample of recent events per source so Copilot understands patterns

    Args:
        sample_events_per_source: How many recent raw events to return per
                                  source for pattern recognition (default 3).
    Returns:
        JSON string describing log structure, ready for Copilot to parse.
    """
    import httpx, os

    LOGINSIGHT_BASE = os.environ["LOGINSIGHT_BASE_URL"]   # e.g. https://loginsight.example.com
    LOGINSIGHT_TOKEN = os.environ["LOGINSIGHT_API_TOKEN"]

    headers = {"Authorization": f"Bearer {LOGINSIGHT_TOKEN}"}

    # 1. Fetch available log sources / datasets
    sources_resp = await httpx.AsyncClient().get(
        f"{LOGINSIGHT_BASE}/api/v1/datasets",
        headers=headers,
        timeout=15,
    )
    sources_resp.raise_for_status()
    sources = sources_resp.json().get("datasets", [])

    schema: dict = {}

    async with httpx.AsyncClient() as client:
        for source in sources:
            source_id = source["id"]
            source_name = source.get("name", source_id)

            # 2. Fetch field definitions for this source
            fields_resp = await client.get(
                f"{LOGINSIGHT_BASE}/api/v1/datasets/{source_id}/fields",
                headers=headers,
                timeout=15,
            )
            fields = fields_resp.json().get("fields", []) if fields_resp.is_success else []

            # 3. Fetch a small sample of recent events
            events_resp = await client.post(
                f"{LOGINSIGHT_BASE}/api/v1/events/query",
                headers=headers,
                json={
                    "dataset": source_id,
                    "limit": sample_events_per_source,
                    "order": "desc",
                },
                timeout=15,
            )
            sample_events = (
                events_resp.json().get("events", []) if events_resp.is_success else []
            )

            # 4. Derive distinct severity levels from sample
            severity_levels = list(
                {e.get("severity", "unknown") for e in sample_events}
            )

            schema[source_name] = {
                "source_id": source_id,
                "fields": [
                    {
                        "name": f.get("name"),
                        "type": f.get("type"),
                        "description": f.get("description", ""),
                    }
                    for f in fields
                ],
                "observed_severity_levels": severity_levels,
                "sample_events": sample_events,  # raw events for pattern recognition
            }

    return json.dumps(schema, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 3 — Combined bootstrap (call this once at session start)
# Returns both DB schema and LoginSight patterns in a single tool call,
# minimising round-trips when Copilot initialises the session.
# ─────────────────────────────────────────────────────────────────────────────
@server.tool()
async def get_full_context() -> str:
    """
    Bootstrap tool — call once at the start of a session.
    Returns database schema AND LoginSight log patterns combined,
    so Copilot has full context in a single round-trip.
    """
    db_schema = await get_database_schema()
    log_schema = await get_loginsight_schema()

    return json.dumps(
        {
            "database_schema": json.loads(db_schema),
            "loginsight_schema": json.loads(log_schema),
            "instructions": (
                "Use database_schema to understand table relationships and write accurate SQL. "
                "Use loginsight_schema to understand log field names, severity levels, "
                "and event patterns when querying for anomalies or trends."
            ),
        },
        indent=2,
    )
