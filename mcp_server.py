#!/usr/bin/env python3
"""AXIOM RED — minimal MCP server exposing recon + attack tools."""
# pip install mcp
from mcp.server.fastmcp import FastMCP
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent.tools.recon import scan_ports, discover_endpoints, fingerprint_tech
from agent.tools.attacks import test_sqli, test_jwt_none, test_config_exposure

mcp = FastMCP("axiom-red")

@mcp.tool()
def recon(target: str) -> dict:
    """Recon a target: open ports, endpoints, technologies."""
    return {"ports": scan_ports(target),
            "endpoints": discover_endpoints(target),
            "tech": fingerprint_tech(target)}

@mcp.tool()
def test_sql_injection(base_url: str, endpoint: str = "/api/v1/search", param: str = "q") -> str:
    f = test_sqli(base_url, endpoint, param)
    return f.description if f else "No SQL injection confirmed."

if __name__ == "__main__":
    mcp.run()
