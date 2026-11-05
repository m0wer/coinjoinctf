"""Minimal bitcoind JSON-RPC client (regtest)."""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from typing import Any

DEFAULT_URL = os.environ.get("CTF_RPC_URL", "http://ctf:ctf@127.0.0.1:18743")


class RPCError(Exception):
    pass


class RPC:
    def __init__(self, url: str = DEFAULT_URL, wallet: str | None = None) -> None:
        creds, host = url.split("://", 1)[1].split("@", 1)
        self._auth = "Basic " + base64.b64encode(creds.encode()).decode()
        self._url = f"http://{host}" + (f"/wallet/{wallet}" if wallet else "")
        self._id = 0

    def call(self, method: str, *params: Any) -> Any:
        self._id += 1
        body = json.dumps({"jsonrpc": "1.0", "id": self._id, "method": method, "params": params})
        req = urllib.request.Request(
            self._url,
            data=body.encode(),
            headers={"Authorization": self._auth, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                payload = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            payload = json.loads(e.read() or b"{}")
            if not payload.get("error"):
                raise RPCError(f"{method}: HTTP {e.code}") from e
        if payload.get("error"):
            raise RPCError(f"{method}: {payload['error'].get('message')}")
        return payload["result"]

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        return lambda *p: self.call(name, *p)


def node(url: str = DEFAULT_URL) -> RPC:
    """Return a wallet RPC for the 'miner' wallet, creating/loading it and maturing coinbase."""
    base = RPC(url)
    wallets = base.listwallets()
    if "miner" not in wallets:
        try:
            base.loadwallet("miner")
        except RPCError:
            base.createwallet("miner")
    w = RPC(url, "miner")
    if base.getblockcount() < 110:
        w.generatetoaddress(110 - base.getblockcount(), w.getnewaddress())
    return w


def mine(w: RPC, n: int = 1) -> list[str]:
    return list(w.generatetoaddress(n, w.getnewaddress()))
