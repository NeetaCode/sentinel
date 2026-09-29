import os

from fastapi import FastAPI, Header, HTTPException

from . import pipeline, store

app = FastAPI(title="Sentinel")

def _auth(key):
    if os.getenv("SENTINEL_API_KEY") and key != os.getenv("SENTINEL_API_KEY"):
        raise HTTPException(401, "bad api key")

@app.get("/health")
def health(): return {"ok": True}

@app.post("/triage")
async def triage(x_api_key: str = Header(None)):
    _auth(x_api_key)
    return await pipeline.run_triage()

@app.get("/pending")
def pending(): return store.list_("pending")

@app.get("/blocked")
def blocked(): return store.list_("blocked")

@app.get("/audit")
def audit(): return store.audit()

def _decide(pid, who, key, approve):
    _auth(key)
    try:
        return pipeline.decide(pid, who, approve)
    except ValueError as e:
        raise HTTPException(404, str(e))

@app.post("/approve/{pid}")
def approve(pid: int, x_approver: str = Header(...), x_api_key: str = Header(None)):
    return _decide(pid, x_approver, x_api_key, True)

@app.post("/reject/{pid}")
def reject(pid: int, x_approver: str = Header(...), x_api_key: str = Header(None)):
    return _decide(pid, x_approver, x_api_key, False)
