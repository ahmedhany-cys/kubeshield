#!/usr/bin/env python3
"""Capture dashboard screenshots from the running laboratory with Playwright.

Usage: python3 e2e/screenshots.py [--url http://127.0.0.1:8080] [--browser-channel chrome]
Requires: pip install playwright httpx  (uses an installed Chrome via --browser-channel, or
`playwright install chromium`).
The admin password is read from the cluster Secret and never written to disk.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import httpx
from playwright.sync_api import sync_playwright
from run_e2e import admin_password

OUT = Path(__file__).resolve().parent.parent / "docs" / "screenshots"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--browser-channel", default=None, help="e.g. 'chrome' to use an installed Chrome")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    api = httpx.Client(base_url=args.url, timeout=30)
    api.post("/api/v1/auth/login", json={"username": "admin", "password": admin_password()}).raise_for_status()
    incidents = api.get("/api/v1/incidents", params={"limit": 50}).json()["items"]
    # Prefer the richest incident (most correlated detections) for the investigation view.
    incident = max(incidents, key=lambda i: (len(i["rules"]), i["event_count"]), default=None)
    images = api.get("/api/v1/images").json()["images"]
    worst = images[0]["id"] if images else None

    shots = [
        ("01-dashboard-overview.png", "/", None),
        ("02-runtime-threat-detection.png", "/threats", None),
        ("03-kubernetes-cluster-overview.png", "/cluster", None),
        ("04-vulnerability-scanning.png", "/vulnerabilities" + (f"?scan={worst}" if worst else ""), None),
        ("05-policy-violations.png", "/policies", None),
        ("06-incident-investigation.png", f"/incidents/{incident['id']}" if incident else "/incidents", None),
        ("07-attack-simulation-results.png", "/simulations", None),
        ("08-mitre-attack-mapping.png", "/mitre", {"width": 2100, "height": 1000}),
        ("09-automated-response-history.png", "/responses", None),
        ("10-network-security.png", "/network", None),
        ("11-settings-system-status.png", "/settings", None),
    ]
    with sync_playwright() as p:
        browser = p.chromium.launch(channel=args.browser_channel) if args.browser_channel else p.chromium.launch()
        ctx = browser.new_context(base_url=args.url, viewport={"width": 1600, "height": 1000},
                                  device_scale_factor=1, color_scheme="dark")
        r = ctx.request.post("/api/v1/auth/login",
                             data={"username": "admin", "password": admin_password()})
        assert r.ok, r.text()
        page = ctx.new_page()
        for name, path, viewport in shots:
            page.set_viewport_size(viewport or {"width": 1600, "height": 1000})
            page.goto(path, wait_until="networkidle")
            page.wait_for_timeout(1500)  # let charts finish their first render
            page.screenshot(path=str(OUT / name), full_page=True)
            print("captured", name)
        browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
