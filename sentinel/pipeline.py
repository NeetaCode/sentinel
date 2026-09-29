import os

from . import agent, config, detector, guardrails, store


async def run_triage():
    out = []
    for e in detector.flag_suspicious():
        ip = e["src_ip"]
        if store.has_open(ip):
            continue
        p = await agent.investigate(ip)
        ok, note = guardrails.check(p, ip)
        status = "pending" if ok else "blocked"
        out.append({"id": store.save(ip, p, status, note), "ip": ip,
                    "action": p.action, "target": p.target, "status": status, "note": note})
    return out

def execute(p):
    """The ONLY code path that changes state. Simulated as append-only files."""
    if p["action"] == "no_action":
        return
    os.makedirs(config.actions_dir(), exist_ok=True)
    with open(os.path.join(config.actions_dir(), p["action"] + ".txt"), "a") as f:
        f.write(p["target"] + "\n")

def decide(pid: int, approver: str, approve: bool):
    p = store.get(pid)
    if not p or p["status"] != "pending":
        raise ValueError("proposal not found or not pending")
    if approve:
        execute(p)
    store.set_status(pid, "approved" if approve else "rejected", approver)
    return store.get(pid)
