"""Record the web demo as a screencast (Playwright + headless Chromium).

    uv run --with playwright python demo/record.py                         # fresh game, dev-mode proof
    uv run --with playwright python demo/record.py --from tmp/talk --real --pace 2.5  # prepared game

Fresh mode clicks through the whole story (stage, setup proof, near miss, public audit, correct
guess and claim, reveal). ``--from DIR`` copies a prepared game (``coinjoinctf stage`` + ``setup``),
so the original stays untouched for a live run, and replays its history instead of the first two
steps. Saves demo.webm (and demo.mp4 if ffmpeg can encode H.264), one screenshot per phase, and the
server time of each step. Fails on any browser console error or error event.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

PORT = 8799


def act(page: Page, *clicks: str, timeout: float = 1_800_000) -> float:
    """Click, then wait for the server's next "idle" event; returns the seconds it took."""
    before = page.evaluate("S.idles")
    t0 = time.time()
    for sel in clicks:
        page.click(sel)
    page.wait_for_function(f"S.idles > {before}", timeout=timeout)
    return time.time() - t0


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--real", action="store_true", help="participants require a real STARK receipt")
    p.add_argument("--from", dest="source", help="prepared state directory (stage + setup done)")
    p.add_argument("--out", default="tmp/recording")
    p.add_argument(
        "--pace", type=float, default=1.0, help="multiply every pause (slower video for narration)"
    )
    a = p.parse_args()
    out, state = Path(a.out), Path(a.out) / "state"
    shutil.rmtree(out, ignore_errors=True)
    if a.source:
        shutil.copytree(a.source, state)
    else:
        state.mkdir(parents=True)
    cmd = ["coinjoinctf", "--state", str(state), *([] if a.real else ["--dev"]), "serve", "--port", str(PORT)]
    server = subprocess.Popen(cmd)
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/api/state")
                break
            except OSError:
                time.sleep(0.2)
        record(out, prepared=bool(a.source), pace=a.pace)
    finally:
        server.kill()


def record(out: Path, prepared: bool, pace: float = 1.0) -> None:
    errors: list[str] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1600, "height": 900}, record_video_dir=str(out),
                                  record_video_size={"width": 1600, "height": 900})  # fmt: skip
        page = ctx.new_page()
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(f"http://127.0.0.1:{PORT}/")
        page.wait_for_timeout(2000 * pace)

        def shot(name: str, seconds: float | None = None, pause: int = 2500) -> None:
            page.wait_for_timeout(pause * pace)
            page.screenshot(path=str(out / f"{name}.png"))
            print(f"{name}: {'' if seconds is None else f'{seconds:.1f} s'}", flush=True)

        def pick(button: str) -> None:
            page.click(button)
            page.wait_for_timeout(1500 * pace)

        if prepared:
            page.click("#btn-replay")
            page.wait_for_function("!S.replaying", timeout=120_000)
            shot("1-history", pause=2000)
        else:
            shot("1-stage", act(page, "#btn-stage"))
            shot("2-setup", act(page, "#btn-setup"))
        pick("#btn-near")
        shot("3-near-miss", act(page, "#btn-play"), pause=3000)
        shot("4-audit", act(page, "#btn-audit"), pause=3500)
        pick("#btn-correct")
        shot("5-win", act(page, "#btn-play"), pause=3000)
        shot("6-reveal", act(page, "#btn-reveal"), pause=4000)
        errors += page.eval_on_selector_all(".ev.err", "els => els.map(e => e.textContent)")
        ctx.close()
        browser.close()
    video = next(out.glob("*.webm")).rename(out / "demo.webm")
    print(f"video: {video}")
    if shutil.which("ffmpeg"):
        mp4 = out / "demo.mp4"
        for codec in ("libx264", "libopenh264"):
            cmd = ["ffmpeg", "-loglevel", "error", "-y", "-i", str(video), "-c:v", codec, "-b:v", "4M",
                   "-pix_fmt", "yuv420p", "-movflags", "+faststart", str(mp4)]  # fmt: skip
            if subprocess.run(cmd, check=False).returncode == 0:
                print(f"video: {mp4} ({codec})")
                break
    if errors:
        print("errors:", *errors, sep="\n  ")
        sys.exit(1)


if __name__ == "__main__":
    main()
