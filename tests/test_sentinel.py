import asyncio
import os

import pytest

from sentinel import detector, gen_logs, pipeline, store
from sentinel.guardrails import Proposal, check, sanitize


@pytest.fixture(scope="module", autouse=True)
def env(tmp_path_factory):
    os.environ["SENTINEL_DATA_DIR"] = str(tmp_path_factory.mktemp("d"))
    os.environ.pop("LLM_BASE_URL", None)
    os.environ.pop("LLM_API_KEY", None)
    gen_logs.generate()

def P(a, t, c): return Proposal(action=a, target=t, confidence=c, reasoning="x")

def test_protected_asset_blocked(): assert not check(P("disable_user", "ceo", 0.99), "1.1.1.1")[0]
def test_low_conf_disable_blocked(): assert not check(P("disable_user", "u", 0.5), "1.1.1.1")[0]
def test_wrong_ip_target_blocked(): assert not check(P("block_ip", "9.9.9.9", 0.99), "1.1.1.1")[0]
def test_ok_block(): assert check(P("block_ip", "1.1.1.1", 0.9), "1.1.1.1")[0]
def test_schema_rejects_bad_action():
    with pytest.raises(Exception):
        P("rm_rf", "x", 0.9)
def test_injection_redacted(): assert "REDACTED" in sanitize(gen_logs.INJECTION)

def test_detector_quality():
    m = detector.train()
    print(m)
    assert m["recall"] >= 0.75 and m["precision"] >= 0.5, m

def test_end_to_end_hitl():
    detector.train()
    res = asyncio.run(pipeline.run_triage())
    by_ip = {r["ip"]: r for r in res}
    print(by_ip)
    assert by_ip["203.0.113.7"]["status"] == "pending"
    assert by_ip["203.0.113.7"]["action"] == "block_ip"   # injection did not flip it to no_action
    assert by_ip["192.0.2.44"]["status"] == "blocked"     # protected account
    assert not os.path.exists(os.path.join(os.environ["SENTINEL_DATA_DIR"], "actions"))  # nothing executed yet
    pipeline.decide(by_ip["203.0.113.7"]["id"], "alice", True)
    assert "203.0.113.7" in open(os.path.join(os.environ["SENTINEL_DATA_DIR"], "actions", "block_ip.txt")).read()
    with pytest.raises(ValueError):
        pipeline.decide(by_ip["192.0.2.44"]["id"], "alice", True)
    assert any(a["who"] == "alice" for a in store.audit())
