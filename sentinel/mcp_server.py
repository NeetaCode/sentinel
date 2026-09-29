"""MCP server: READ-ONLY tools. Nothing here can change state."""
import pandas as pd
from mcp.server.fastmcp import FastMCP

from . import config
from .guardrails import sanitize

mcp = FastMCP("sentinel-tools")
BAD = {"203.0.113.7": 95, "198.51.100.23": 80, "203.0.113.99": 90, "192.0.2.44": 60}

@mcp.tool()
def ip_reputation(ip: str) -> dict:
    """Threat-intel reputation for an IP (stub; swap for AbuseIPDB/VirusTotal)."""
    return {"ip": ip, "abuse_score": BAD.get(ip, 5)}

@mcp.tool()
def asset_info(user: str) -> dict:
    """Role and criticality of a user account."""
    admin = "admin" in user or user in {"ceo"}
    return {"user": user, "role": "admin" if admin else "employee", "criticality": "high" if admin else "low"}

@mcp.tool()
def recent_events(ip: str, limit: int = 10) -> dict:
    """Summary stats and sample of auth events from an IP (notes are sanitized)."""
    df = pd.read_csv(config.csv_path())
    d = df[df.src_ip == ip]
    stats = {
        "attempts": len(d), "fails": int((~d.success.astype(bool)).sum()),
        "successes": int(d.success.astype(bool).sum()), "users": sorted(d.user.unique())[:8],
        "n_users": int(d.user.nunique()), "hours": sorted(int(h) for h in d.hour.unique()),
        "countries": sorted(d.country.unique().tolist()),
    }
    d = d.drop_duplicates("note").head(limit)
    events = [{"user": r.user, "success": bool(r.success), "hour": int(r.hour), "note": sanitize(r.note)}
              for r in d.itertuples()]
    return {"stats": stats, "events": events}

if __name__ == "__main__":
    mcp.run()
