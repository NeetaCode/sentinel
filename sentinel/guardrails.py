import re
from typing import Literal

from pydantic import BaseModel, Field

PROTECTED = {"10.0.0.1", "break-glass-admin", "ceo"}
INJECTION = re.compile(r"ignore (all |previous |prior )|system prompt|you are now|disregard|mark .* as", re.IGNORECASE)

class Proposal(BaseModel):
    action: Literal["block_ip", "disable_user", "escalate", "no_action"]
    target: str
    confidence: float = Field(ge=0, le=1)
    reasoning: str = Field(max_length=800)

def sanitize(text) -> str:
    """Logs are attacker-controlled: truncate and redact likely prompt injection."""
    t = str(text)[:200]
    return "[REDACTED: possible prompt injection]" if INJECTION.search(t) else t

def check(p: Proposal, entity_ip: str):
    """Returns (ok, note). Not ok => forced to 'blocked' (human must handle manually)."""
    if p.target in PROTECTED:
        return False, f"Protected asset '{p.target}': automated action forbidden, escalate"
    if p.action == "block_ip" and p.target != entity_ip:
        return False, "block_ip target must be the flagged IP"
    if p.action == "disable_user" and p.confidence < 0.85:
        return False, "Confidence too low for disruptive action"
    if p.action == "no_action" and p.confidence < 0.9:
        return False, "Low-confidence dismissal needs human review"
    return True, "ok"
