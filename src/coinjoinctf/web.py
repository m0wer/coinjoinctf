"""Web demo: the stage's transaction graph growing live, and the protocol timeline of each entry.

Single process, single game. Operations run in a worker thread; every event goes to an
append-only log that the page streams over SSE from any offset (reconnect-safe).
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import bitcointx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from coinjoinctf.rpc import RPC, node
from coinjoinctf.session import Session
from coinjoinctf.stage import StageConfig

STATIC = Path(__file__).parent / "static"


class Hub:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.busy: str | None = None
        self.block_delay = 0.0

    def emit(self, kind: str, **data: Any) -> None:
        with self.lock:
            self.events.append({"i": len(self.events), "kind": kind, **data})
        if kind == "block" and self.block_delay:
            time.sleep(self.block_delay)

    def since(self, i: int) -> list[dict[str, Any]]:
        with self.lock:
            return self.events[i:]


class StageReq(BaseModel):
    makers: int = 8
    takers: int = 3
    block_delay: float = 0.25


class PlayReq(BaseModel):
    tips: list[str]
    stall: bool = False


def create_app(state: Path, dev: bool, rpc: RPC | None = None) -> FastAPI:
    hub = Hub()
    s = Session(rpc or node(), state, hub.emit, dev_proof=dev)
    app = FastAPI(title="coinjoinctf")
    app.state.hub = hub
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    def run(name: str, fn: Callable[[], Any]) -> dict[str, str]:
        with hub.lock:
            if hub.busy:
                raise HTTPException(409, f"busy: {hub.busy}")
            hub.busy = name

        def target() -> None:
            bitcointx.select_chain_params("bitcoin/regtest")  # chain params are thread-local
            try:
                fn()
            except Exception as e:  # surfaced to the page, the server keeps running
                hub.emit("error", message=f"{type(e).__name__}: {e}")
            finally:
                hub.busy = None
                hub.block_delay = 0.0
                hub.emit("idle", op=name)

        threading.Thread(target=target, daemon=True).start()
        return {"started": name}

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/state")
    def get_state() -> dict[str, Any]:
        pub = s.stage.public() if s.stage else None
        return {
            "stage": pub,
            "manifest": s.manifest.model_dump() if s.manifest else None,
            "entries": s.entries,
            "busy": hub.busy,
            "dev": dev,
            "offset": len(hub.events),
        }

    @app.get("/api/events")
    async def events(request: Request, since: int = 0) -> StreamingResponse:
        last = request.headers.get("last-event-id")  # browser reconnect: resume, do not replay

        async def stream() -> AsyncIterator[str]:
            i = int(last) + 1 if last and last.isdigit() else since
            while not await request.is_disconnected():
                new = hub.since(i)
                for e in new:
                    yield f"id: {e['i']}\ndata: {json.dumps(e, default=str)}\n\n"
                i += len(new)
                await asyncio.sleep(0.1)

        return StreamingResponse(stream(), media_type="text/event-stream")

    @app.post("/api/stage")
    def stage(req: StageReq) -> dict[str, str]:
        hub.block_delay = req.block_delay
        return run("stage", lambda: s.run_stage(StageConfig(n_makers=req.makers, n_takers=req.takers)))

    @app.post("/api/setup")
    def setup() -> dict[str, str]:
        return run("setup", s.setup)

    @app.post("/api/play")
    def play(req: PlayReq) -> dict[str, str]:
        return run("play", lambda: s.play(req.tips, stall=req.stall))

    @app.post("/api/audit/{name}")
    def audit(name: str) -> dict[str, str]:
        if name not in s.entries:
            raise HTTPException(404, "no such finished entry")
        return run("audit", lambda: s.audit(name))

    @app.post("/api/reveal")
    def reveal() -> dict[str, str]:
        return run("reveal", s.reveal)

    @app.get("/api/demo-guess/{kind}")
    def demo_guess(kind: str) -> list[str]:
        """Host-side shortcut for presentations (a real participant has no such endpoint)."""
        if not s.stage:
            raise HTTPException(400, "run the stage first")
        return s.demo_guesses()[kind]

    return app


def serve(state: Path, port: int, *, dev: bool) -> None:
    import uvicorn

    uvicorn.run(create_app(state, dev), host="127.0.0.1", port=port, log_level="warning")
