#!/usr/bin/env python3
"""Inject a small warning banner into the per-image report pages for any
image scan.sh's --staleness-check flagged as behind its build repo's latest
published tag.

Those per-image pages are rendered by the upstream vexscan-dashboard.py
(fetched fresh from the vexscan repo at scan time), which has no knowledge of
our staleness field. This is a best-effort post-processing pass over its
already-rendered output: any image it can't confidently match to a rendered
page is skipped with a warning rather than guessed at, and it never touches
vexscan-dashboard.py's own findings/verdicts on the page.
"""
import html
import json
import os
import re
import sys

BANNER_MARKER = "banner-staleness"


def esc(value):
    return html.escape(str(value), quote=True)


def load_staleness_images(json_path):
    with open(json_path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    images = (doc.get("staleness") or {}).get("images") or []
    return [img for img in images if img.get("status") == "NEEDS_UPDATE"]


def build_target_href_map(run_index_path):
    """Map each target's exact image ref (as rendered by vexscan-dashboard.py)
    to its per-image page's href, by reading that run's own index page -
    avoids having to reimplement vexscan-dashboard.py's filename slugging."""
    with open(run_index_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    mapping = {}
    for m in re.finditer(r'<a href="([^"]+\.html)"[^>]*>([^<]+)</a>', content):
        href, target = m.group(1), html.unescape(m.group(2)).strip()
        mapping[target] = href
    return mapping


def render_banner(img, scan_id):
    findings_current = img.get("findings_current") or {}
    findings_latest = img.get("findings_latest")
    delta = None
    if findings_latest is not None:
        delta = sum(findings_current.values()) - sum(findings_latest.values())

    name = img.get("image_name") or img.get("image") or "this image"
    latest_tag = img.get("latest_tag") or "a newer tag"
    text = "A newer tag is available: %s %s" % (esc(name), esc(latest_tag))
    if delta is not None and delta > 0:
        text += " &mdash; fixes %d additional CVE%s" % (delta, "" if delta == 1 else "s")
    text += '. See the <a href="../index.html#%s">staleness summary</a>.' % esc(scan_id)
    return (
        '<div class="banner banner-warn %s"><span class="icon">&#9888;</span>'
        "<span>%s</span></div>"
    ) % (BANNER_MARKER, text)


def inject(page_path, banner_html):
    with open(page_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    if BANNER_MARKER in content:
        return False  # already injected; keep re-runs idempotent

    idx = content.find('<div class="banner')
    if idx == -1:
        idx = content.find("</main>")
    if idx == -1:
        return False

    content = content[:idx] + banner_html + content[idx:]
    with open(page_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return True


def main():
    if len(sys.argv) != 4:
        print(
            "usage: inject_staleness_banners.py <scan.json> <run-html-dir> <scan-id>",
            file=sys.stderr,
        )
        return 1
    json_path, run_html_dir, scan_id = sys.argv[1:4]

    try:
        stale_images = load_staleness_images(json_path)
    except (OSError, ValueError) as exc:
        print(
            "Warning: could not read staleness data from %s (%s); skipping banner injection"
            % (json_path, exc),
            file=sys.stderr,
        )
        return 0
    if not stale_images:
        return 0

    run_index_path = os.path.join(run_html_dir, "index.html")
    try:
        target_href = build_target_href_map(run_index_path)
    except OSError as exc:
        print(
            "Warning: could not read %s (%s); skipping banner injection" % (run_index_path, exc),
            file=sys.stderr,
        )
        return 0

    injected = 0
    for img in stale_images:
        target = img.get("image")
        href = target_href.get(target)
        if not href:
            print(
                "Warning: no rendered page found for stale image %s; skipping its banner" % target,
                file=sys.stderr,
            )
            continue
        page_path = os.path.join(run_html_dir, href)
        banner_html = render_banner(img, scan_id)
        try:
            if inject(page_path, banner_html):
                injected += 1
        except OSError as exc:
            print("Warning: could not inject banner into %s (%s)" % (page_path, exc), file=sys.stderr)

    print("Injected staleness banner into %d page(s)" % injected)
    return 0


if __name__ == "__main__":
    sys.exit(main())
