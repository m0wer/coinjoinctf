"""Web demo API end to end (regtest, dev-mode proofs): the page's whole flow through HTTP."""

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from coinjoinctf import zk
from coinjoinctf.rpc import RPCError, node
from coinjoinctf.web import create_app

pytestmark = [pytest.mark.regtest, pytest.mark.skipif(not zk.BINARY.exists(), reason="zk binary not built")]


def _wait(client: TestClient, timeout: float = 120) -> None:
    end = time.time() + timeout
    while client.get("/api/state").json()["busy"]:
        assert time.time() < end, "operation did not finish"
        time.sleep(0.2)


def test_full_flow_over_http(tmp_path: Path) -> None:
    try:
        rpc = node()
    except (RPCError, OSError):
        pytest.skip("regtest node not running")
    app = create_app(tmp_path, dev=True, rpc=rpc)
    c = TestClient(app)
    assert c.get("/").status_code == 200 and c.get("/static/app.js").status_code == 200
    assert c.post("/api/stage", json={"makers": 6, "takers": 2, "block_delay": 0}).json() == {
        "started": "stage"
    }
    assert c.post("/api/setup").status_code == 409  # one operation at a time
    _wait(c)
    state = c.get("/api/state").json()
    assert (
        state["stage"]["txs"] and not {"tips", "tumbler_seed", "owners", "host_txids"} & state["stage"].keys()
    )
    c.post("/api/setup")
    _wait(c)
    near = c.get("/api/demo-guess/near_miss").json()
    c.post("/api/play", json={"tips": near})
    _wait(c)
    c.post("/api/audit/entry1")
    _wait(c)
    c.post("/api/play", json={"tips": c.get("/api/demo-guess/correct").json()})
    _wait(c)
    c.post("/api/reveal")
    _wait(c)
    events = app.state.hub.events
    kinds = [e["kind"] for e in events]
    assert "error" not in kinds, [e for e in events if e["kind"] == "error"]
    assert kinds.count("tx") >= len(state["stage"]["txs"])  # warm-up blocks precede the history
    assert [k for k in kinds if k in ("settled", "claimed")] == ["settled", "claimed"]
    assert next(e for e in events if e["kind"] == "audit")["verdict"].startswith("lost")
    assert c.get("/api/state").json()["entries"] == ["entry1", "entry2"]
