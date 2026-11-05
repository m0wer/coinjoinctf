"""Record the web demo as a screencast (Playwright + headless Chromium).

    uv run --with playwright python demo/record.py [--real] [--out tmp/recording]

Starts a server on a fresh state directory, clicks through the story like a presenter (stage,
setup proof, near miss, public audit, correct guess and claim, reveal), saves a .webm video and
one screenshot per phase, and fails on any browser console error.
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


def act(page: Page, *clicks: str, timeout: float = 1_800_000) -> None:
    """Click, then wait for the server's next \"idle\" event (robust for instant operations too)."""
    before = page.evaluate("S.idles")
    for sel in clicks:
        page.click(sel)
        page.wait_for_timeout(700)
    page.wait_for_function(f"S.idles > {before}", timeout=timeout)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--real", action="store_true", help="real STARK setup proof (minutes) instead of dev mode")
    p.add_argument("--out", default="tmp/recording")
    a = p.parse_args()
    out, state = Path(a.out), Path(a.out) / "state"
    shutil.rmtree(out, ignore_errors=True)
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
        record(out)
    finally:
        server.kill()


def record(out: Path) -> None:
    errors: list[str] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1600, "height": 900}, record_video_dir=str(out),
                                  record_video_size={"width": 1600, "height": 900})  # fmt: skip
        page = ctx.new_page()
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(f"http://127.0.0.1:{PORT}/")
        page.wait_for_timeout(1500)

        def step(name: str, *clicks: str, pause: int = 2500) -> None:
            act(page, *clicks)
            page.wait_for_timeout(pause)
            page.screenshot(path=str(out / f"{name}.png"))
            print(f"{name}: done", flush=True)

        step("1-stage", "#btn-stage")
        step("2-setup", "#btn-setup")
        page.click("#btn-near")
        page.wait_for_timeout(1500)
        step("3-near-miss", "#btn-play", pause=3000)
        step("4-audit", "#btn-audit", pause=3000)
        page.click("#btn-correct")
        page.wait_for_timeout(1500)
        step("5-win", "#btn-play", pause=3000)
        step("6-reveal", "#btn-reveal", pause=4000)
        ctx.close()
        browser.close()
    video = next(out.glob("*.webm"))
    video.rename(out / "demo.webm")
    print(f"video: {out / 'demo.webm'}")
    if errors:
        print("browser errors:", *errors, sep="\n  ")
        sys.exit(1)


if __name__ == "__main__":
    main()
