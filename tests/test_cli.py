"""Narrated CLI demo end to end (regtest, dev-mode proofs): every event has a printer."""

import re
from pathlib import Path

import pytest

from coinjoinctf import zk
from coinjoinctf.cli import main
from coinjoinctf.rpc import RPCError, node

pytestmark = [pytest.mark.regtest, pytest.mark.skipif(not zk.BINARY.exists(), reason="zk binary not built")]


def test_demo_tells_the_whole_story(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    try:
        node()
    except (RPCError, OSError):
        pytest.skip("regtest node not running")
    main(["--dev", "--state", str(tmp_path), "demo", "--fresh", "--makers", "6", "--takers", "2"])
    out = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)
    assert re.search(r"^  [a-z_]+$", out, re.M) is None, "an event fell through to the default printer"
    order = ["history frozen", "journal: n_tips=", "Entry entry1", "no win", "host settled",
             "Public audit of entry1: lost", "Entry entry2", "WIN", "claimed", "Reveal"]  # fmt: skip
    positions = [out.index(s) for s in order]
    assert positions == sorted(positions)
    assert (tmp_path / "stage.json").stat().st_mode & 0o777 == 0o600
    assert sorted(p.name for p in (tmp_path / "entries").iterdir()) == ["entry1.json", "entry2.json"]
