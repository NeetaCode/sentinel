# Sentinel: AI SOC triage agent with human approval (100% free stack)

**Problem:** security teams drown in login alerts. **Sentinel** finds suspicious activity with ML, lets an AI agent
investigate it with read-only tools, and hands a ready-made recommendation to a human, who is the only one who can act.

    auth logs -> ML anomaly detector -> AI agent (MCP tools, read-only) -> guardrails -> approval queue -> HUMAN -> action -> audit log

## Free by design
| Piece | Free choice |
|---|---|
| ML / libs | scikit-learn, FastAPI, Pydantic, MCP SDK (all open source) |
| LLM | Local Ollama (or offline mock mode, or any free OpenAI-compatible endpoint) |
| Hosting | Your own machine via Docker (same compose deploys to any VPS later) |
| Scheduling | `scheduler` container in compose (or crontab) |
| CI | GitHub Actions on a public repo, plus a local pre-push hook |

## Quick start (no key, no Docker)
    pip install -r requirements.txt
    make demo                                   # gen logs -> train -> triage -> list
    python -m sentinel.cli approve 1 --by alice # human executes -> data/actions/block_ip.txt
    python -m sentinel.cli audit
    make test

## Docker (API + scheduler)
    cp .env.example .env
    docker compose up -d --build                # http://localhost:8000/docs
    curl localhost:8000/pending
    curl -X POST localhost:8000/approve/1 -H "X-Approver: alice" -H "X-API-Key: change-me"

## Free local LLM
    docker compose --profile llm up -d --build
    docker compose exec ollama ollama pull llama3.1:8b
    # .env: LLM_BASE_URL=http://ollama:11434/v1  LLM_MODEL=llama3.1:8b  LLM_API_KEY=x
Outside Docker: `export LLM_BASE_URL=http://localhost:11434/v1 LLM_MODEL=llama3.1:8b LLM_API_KEY=x`.
The model must support tool calling; on any failure the agent falls back to `escalate`.

## Free CI
`git init && sh scripts/install-hooks.sh` runs lint + tests before every push. `.github/workflows/ci.yml` does the
same plus a Docker build and Trivy scan on GitHub (free for public repos).

## Security design
- MCP tools are read-only; the only state change is `pipeline.execute`, reachable only through human approval.
- Logs are untrusted: truncated and injection-filtered at the MCP boundary; the prompt treats tool output as data.
- Output is schema-validated; guardrails cover protected assets, target must equal the flagged IP, confidence floors.
- Every decision is written to the `audit` table.
