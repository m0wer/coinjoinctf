from pathlib import Path
from unittest.mock import Mock

from fastapi.testclient import TestClient

from coinjoinctf.web import create_app


def test_console_discloses_demo_and_fairness_limits(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, dev=True, rpc=Mock()))
    page = client.get("/").text
    assert "Host demo console (regtest only)" in page
    assert "not a participant interface" in page
    assert "probabilistic cut-and-choose" in page
    assert "Reveal answer (host only)" in page
    assert "Near miss (host shortcut)" in page
