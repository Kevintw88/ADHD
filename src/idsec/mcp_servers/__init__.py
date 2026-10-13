"""唯讀 MCP Servers。每個模組可用 `python -m idsec.mcp_servers.<name>` 以 stdio 啟動。"""

SERVERS = {
    "ad-discovery": "idsec.mcp_servers.ad_discovery",
    "entra-graph": "idsec.mcp_servers.entra_graph",
    "bloodhound": "idsec.mcp_servers.bloodhound",
    "assessment-reports": "idsec.mcp_servers.assessment_reports",
}
