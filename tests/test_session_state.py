"""Private state must never be created with a public permission window."""

import os
import stat
from pathlib import Path
from unittest.mock import Mock

import pytest

from coinjoinctf import session


@pytest.mark.parametrize("umask", [0o000, 0o022])
@pytest.mark.parametrize("existing", [False, True])
def test_private_write_is_restrictive_before_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    umask: int,
    existing: bool,
) -> None:
    target = tmp_path / "host.json"
    if existing:
        target.write_text("old")
        target.chmod(0o644)
    mkstemp = session.tempfile.mkstemp
    observed = []

    def create(*args, **kwargs):
        fd, name = mkstemp(*args, **kwargs)
        observed.append(stat.S_IMODE(os.fstat(fd).st_mode))
        assert os.fstat(fd).st_size == 0
        assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o600
        return fd, name

    monkeypatch.setattr(session.tempfile, "mkstemp", create)
    previous = os.umask(umask)
    try:
        session._write_private(target, "secret")
    finally:
        os.umask(previous)
    assert observed == [0o600]
    assert target.read_text() == "secret"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize("operation", ["replace", "fsync"])
def test_failed_write_preserves_previous_private_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    target = tmp_path / "host.json"
    session._write_private(target, "old")
    monkeypatch.setattr(session.os, operation, Mock(side_effect=OSError("failed write")))
    with pytest.raises(OSError, match="failed write"):
        session._write_private(target, "new")
    assert target.read_text() == "old"
    assert list(tmp_path.iterdir()) == [target]


def test_loading_existing_or_partial_state_never_starts_expensive_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prove = Mock(side_effect=AssertionError("unexpected proof generation"))
    monkeypatch.setattr(session.zk, "prove", prove)
    monkeypatch.setattr(session, "Stage", Mock(side_effect=AssertionError("unexpected stage generation")))
    # An absent manifest/receipt is not an instruction to regenerate either one.
    session._write_private(tmp_path / "host.json", '{"r": "' + "00" * 32 + '"}')
    loaded = session.Session(Mock(), tmp_path)
    assert loaded.manifest is None
    prove.assert_not_called()


@pytest.mark.parametrize("contents", [b"partial receipt", b"older guest receipt"])
def test_invalid_receipt_is_preserved_and_never_regenerated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    contents: bytes,
) -> None:
    receipt = tmp_path / "setup.receipt"
    receipt.write_bytes(contents)
    monkeypatch.setattr(session.zk, "_run", Mock(side_effect=session.zk.SetupProofError("invalid receipt")))
    prove = Mock(side_effect=AssertionError("unexpected proof generation"))
    monkeypatch.setattr(session.zk, "prove", prove)
    with pytest.raises(session.zk.SetupProofError, match="preserve the prepared state and explicitly rerun"):
        session.zk.verify_receipt(receipt)
    assert receipt.read_bytes() == contents
    prove.assert_not_called()
