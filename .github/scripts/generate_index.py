#!/usr/bin/env python3
"""generate_index.py -- build the landing page for the vexscan report site.

Each daily/release run renders a vexscan batch report into its own directory
under reports/html/<scan-id>/ (an index plus one page per image, written by
contrib/vexscan-dashboard.py). This script writes the top-level
reports/html/index.html that lists every one of those runs, newest first, with
a per-run summary read out of the sibling reports/<scan-id>.json.

The look is lifted from github.com/cwayne18/rke2-toolbox's scan_to_html.py
(MIT, same author): the Rancher Dashboard "Modern Light" palette, the same
header, card grid and dark-mode toggle. Standard library only; no network.

    python3 .github/scripts/generate_index.py reports/html
"""

import json
import os
import re
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Verdict bucketing -- mirrors contrib/vexscan-dashboard.py's bucket_of so the
# per-run counts on this page agree with the numbers on each run's own index.
# ---------------------------------------------------------------------------

BUCKET_AFFECTED = "affected"
BUCKET_VEXED = "vexed"
BUCKET_UNDETERMINED = "undetermined"
BUCKET_RULED_OUT = "ruled-out"

EXCULPATORY = ("not_affected", "fixed")

SEVERITY_RANK = {
    "CRITICAL": 0, "HIGH": 1, "UNKNOWN": 2, "MEDIUM": 3, "LOW": 4, "NONE": 5,
}


def bucket_of(finding):
    status = finding.get("status", "")
    if status in ("linked", "reachable"):
        vex = finding.get("vex") or {}
        return BUCKET_VEXED if vex.get("status") in EXCULPATORY else BUCKET_AFFECTED
    if status in ("not_present", "not_in_execute_path"):
        return BUCKET_RULED_OUT
    return BUCKET_UNDETERMINED


def display_severity(finding):
    sev = (finding.get("severity") or "").strip()
    return sev if sev else "UNKNOWN"


# ---------------------------------------------------------------------------
# Styling -- Rancher Dashboard "Modern Light" palette + dark mode.
# ---------------------------------------------------------------------------

CSS = """
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&family=Lato:ital,wght@0,400;0,700;1,400&family=Roboto+Mono:wght@400;500&display=swap');

:root {
  --body-bg:         #FFFFFF;
  --body-text:       #141419;
  --muted:           #6C6C76;
  --border:          #DCDEE7;
  --box-bg:          #F4F5FA;
  --header-bg:       #FFFFFF;
  --link:            #1F67DB;
  --card-bg:         #FFFFFF;
  --sev-critical:    #B13333;
  --sev-high:        #E45C1E;
  --sev-medium:      #E5A200;
  --sev-low:         #1F67DB;
  --ok:              #1A7A41;
  --badge-scheduled: #1F67DB;
  --badge-release:   #6A4CC7;
}

*, *::before, *::after { box-sizing: border-box; }

html, body {
  margin: 0; padding: 0;
  background: var(--body-bg);
  color: var(--body-text);
  font-family: 'Lato', -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
  font-size: 14px;
  line-height: 1.6;
}

.page-header {
  background: var(--header-bg);
  border-bottom: 1px solid var(--border);
  padding: 0 32px;
  height: 55px;
  display: flex;
  align-items: center;
  gap: 12px;
  position: sticky;
  top: 0;
  z-index: 100;
  box-shadow: 0 1px 4px rgba(0,0,0,.06);
}
.page-header .brand {
  font-family: 'Poppins', sans-serif;
  font-weight: 600;
  font-size: 17px;
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--body-text);
  text-decoration: none;
}
.page-header .brand svg { width: 26px; height: 26px; flex-shrink: 0; }
.page-header .subtitle {
  font-size: 13px;
  color: var(--muted);
  margin-left: 4px;
}

.page-content { max-width: 1200px; margin: 0 auto; padding: 28px 24px 64px; }

h1 { font-family: 'Poppins', sans-serif; font-size: 22px; font-weight: 600; margin: 0 0 4px; }
.page-sub { color: var(--muted); font-size: 13px; margin: 0 0 24px; }
h2 {
  font-family: 'Poppins', sans-serif;
  font-size: 16px; font-weight: 600; margin: 32px 0 12px;
  display: flex; align-items: baseline; gap: 10px;
}
h2 .sub-count {
  font-size: 12px; font-weight: 600; color: var(--muted);
  background: var(--box-bg); border: 1px solid var(--border);
  border-radius: 999px; padding: 1px 9px;
}

.filter-bar { margin: 0 0 20px; }
.filter-bar input {
  width: 100%; max-width: 420px;
  padding: 8px 12px;
  font: inherit; font-size: 13px;
  color: var(--body-text); background: var(--body-bg);
  border: 1px solid var(--border); border-radius: 6px;
}
.filter-bar input:focus { outline: 2px solid var(--link); outline-offset: -1px; }

.reports-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 12px;
}

.report-card {
  display: block;
  border: 1px solid var(--border);
  border-left-width: 4px;
  border-radius: 8px;
  padding: 14px 16px;
  background: var(--card-bg);
  text-decoration: none;
  color: inherit;
  transition: border-color .15s ease, box-shadow .15s ease;
}
.report-card:hover { border-color: var(--link); box-shadow: 0 2px 10px rgba(0,0,0,.08); }
.report-card.kind-scheduled { border-left-color: var(--badge-scheduled); }
.report-card.kind-release   { border-left-color: var(--badge-release); }

.rc-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; }
.rc-name { font-family: 'Roboto Mono', monospace; font-weight: 500; font-size: 14px; word-break: break-all; }
.rc-date { color: var(--muted); font-size: 12px; margin-top: 2px; }
.rc-arrow { color: var(--muted); font-size: 16px; flex: 0 0 auto; }

.rc-badges { margin-top: 10px; display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.badge {
  display: inline-flex; align-items: center;
  padding: 1px 8px; border-radius: 999px;
  font-size: 11px; font-weight: 700; letter-spacing: .03em;
  border: 1px solid transparent;
}
.badge-scheduled { background: rgba(31,103,219,.12); color: var(--badge-scheduled); border-color: rgba(31,103,219,.35); }
.badge-release   { background: rgba(106,76,199,.12); color: var(--badge-release);   border-color: rgba(106,76,199,.35); }
.badge-clear     { background: rgba(26,122,65,.12);  color: var(--ok);              border-color: rgba(26,122,65,.35); }
.badge-affected  { background: var(--sev-critical);  color: #FFFFFF;                border-color: #7C0015; }
.badge-worst-CRITICAL { background: var(--sev-critical); color:#FFF; border-color:#7C0015; }
.badge-worst-HIGH     { background: var(--sev-high);     color:#FFF; border-color:#B03A0A; }
.badge-worst-MEDIUM   { background: var(--sev-medium);   color:#473900; border-color:#E5A200; }
.badge-worst-LOW      { background: rgba(31,103,219,.15); color: var(--sev-low); border-color: rgba(31,103,219,.4); }
.badge-worst-UNKNOWN  { background: #6C6C76; color:#FFF; border-color:#4A4A52; }
.rc-meta { color: var(--muted); font-size: 12px; }

.empty-state { color: var(--muted); font-style: italic; }

.page-footer {
  margin-top: 44px; padding-top: 16px;
  border-top: 1px solid var(--border);
  color: var(--muted); font-size: 12px;
}

.theme-toggle {
  margin-left: auto;
  display: inline-flex; align-items: center; justify-content: center;
  width: 34px; height: 34px; padding: 0;
  font-size: 15px; line-height: 1; cursor: pointer;
  background: var(--box-bg); color: var(--body-text);
  border: 1px solid var(--border); border-radius: 8px;
}
.theme-toggle:hover { border-color: var(--link); }
.theme-toggle .icon-dark { display: none; }
:root[data-theme="dark"] .theme-toggle .icon-light { display: none; }
:root[data-theme="dark"] .theme-toggle .icon-dark { display: inline; }

:root[data-theme="dark"] {
  --body-bg:   #16171C;
  --body-text: #E6E6EC;
  --muted:     #9B9BA6;
  --border:    #2D2F39;
  --box-bg:    #1E1F26;
  --header-bg: #1A1B21;
  --link:      #5B9BFF;
  --card-bg:   #1A1B21;
}
:root[data-theme="dark"] .page-header { box-shadow: 0 1px 4px rgba(0,0,0,.4); }
"""

THEME_HEAD = """<script>
(function () {
  try {
    var stored = localStorage.getItem('rke2-vexscan-theme');
    var prefersDark = window.matchMedia &&
      window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (stored === 'dark' || (!stored && prefersDark)) {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
  } catch (e) {}
})();
</script>"""

PAGE_SCRIPT = """<script>
function toggleTheme() {
  var d = document.documentElement;
  var dark = d.getAttribute('data-theme') === 'dark';
  if (dark) { d.removeAttribute('data-theme'); }
  else { d.setAttribute('data-theme', 'dark'); }
  try { localStorage.setItem('rke2-vexscan-theme', dark ? 'light' : 'dark'); } catch (e) {}
}
function filterReports(input) {
  var q = input.value.trim().toLowerCase();
  var cards = document.querySelectorAll('.report-card');
  for (var i = 0; i < cards.length; i++) {
    var hit = !q || cards[i].dataset.search.indexOf(q) !== -1;
    cards[i].style.display = hit ? '' : 'none';
  }
}
</script>"""

LOGO_SVG = (
    '<svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" '
    'aria-hidden="true">'
    '<rect x="2" y="2" width="28" height="28" rx="7" fill="#1F67DB"/>'
    '<path d="M9 16.2l4.6 4.6L23 11.4" stroke="white" stroke-width="2.6" '
    'stroke-linecap="round" stroke-linejoin="round"/>'
    "</svg>"
)

THEME_TOGGLE = (
    '<button type="button" class="theme-toggle" aria-label="Toggle dark mode" '
    'title="Toggle dark mode" onclick="toggleTheme()">'
    '<span class="icon-light" aria-hidden="true">&#127769;</span>'
    '<span class="icon-dark" aria-hidden="true">&#9728;</span>'
    "</button>"
)


def esc(text):
    import html
    return html.escape("" if text is None else str(text), quote=True)


# ---------------------------------------------------------------------------
# Reading a run's summary
# ---------------------------------------------------------------------------


def _iter_results(doc):
    if isinstance(doc.get("results"), list):
        return [r for r in doc["results"] if r]
    if "findings" in doc:
        return [doc]
    return []


def summarize_run(json_path):
    """Return (targets, affected, vexed, worst_sev) for a batch JSON, or None."""
    try:
        with open(json_path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    results = _iter_results(doc)
    affected = 0
    vexed = 0
    worst = None
    for res in results:
        for finding in res.get("findings") or []:
            b = bucket_of(finding)
            if b == BUCKET_AFFECTED:
                affected += 1
                sev = display_severity(finding)
                if worst is None or SEVERITY_RANK.get(sev, 6) < SEVERITY_RANK.get(worst, 6):
                    worst = sev
            elif b == BUCKET_VEXED:
                vexed += 1
    targets = doc.get("targets") or len(results)
    return {"targets": targets, "affected": affected, "vexed": vexed, "worst": worst}


_DATE_RE = re.compile(r"(\d{8})")


def parse_date(scan_id):
    m = _DATE_RE.search(scan_id)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y%m%d")
        except ValueError:
            pass
    return None


def run_kind(scan_id):
    return "scheduled" if re.match(r"scan-\d{8}-\d+$", scan_id) else "release"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_card(scan_id, summary):
    kind = run_kind(scan_id)
    date = parse_date(scan_id)
    date_str = date.strftime("%B %d, %Y") if date else ""
    badge_label = "Scheduled" if kind == "scheduled" else "Release"

    badges = ['<span class="badge badge-%s">%s</span>' % (kind, badge_label)]
    meta = ""
    if summary:
        if summary["affected"] > 0:
            badges.append('<span class="badge badge-affected">%d affected</span>' % summary["affected"])
            if summary["worst"]:
                badges.append('<span class="badge badge-worst-%s">%s</span>'
                              % (esc(summary["worst"]), esc(summary["worst"])))
        else:
            badges.append('<span class="badge badge-clear">clear</span>')
        meta = '<span class="rc-meta">%d images · %d vexed</span>' % (
            summary["targets"], summary["vexed"])

    search_key = ("%s %s %s" % (scan_id, date_str, badge_label)).lower()
    return (
        '<a class="report-card kind-%s" href="%s/index.html" data-search="%s">'
        '<div class="rc-top"><div>'
        '<div class="rc-name">%s</div>'
        '%s'
        "</div><span class=\"rc-arrow\">&#8594;</span></div>"
        '<div class="rc-badges">%s %s</div>'
        "</a>"
    ) % (
        kind, esc(scan_id), esc(search_key), esc(scan_id),
        ('<div class="rc-date">%s</div>' % esc(date_str)) if date_str else "",
        " ".join(badges), meta,
    )


def render_section(title, ids, summaries):
    if not ids:
        return ""
    cards = "\n".join(render_card(sid, summaries.get(sid)) for sid in ids)
    return (
        '<h2>%s<span class="sub-count">%d</span></h2>'
        '<div class="reports-grid">\n%s\n</div>'
    ) % (esc(title), len(ids), cards)


def generate_index(html_dir):
    html_dir = os.path.abspath(html_dir)
    reports_dir = os.path.dirname(html_dir)

    run_ids = []
    for entry in os.listdir(html_dir):
        full = os.path.join(html_dir, entry)
        if os.path.isdir(full) and os.path.isfile(os.path.join(full, "index.html")):
            run_ids.append(entry)

    def sort_key(sid):
        date = parse_date(sid)
        return (date or datetime.min, sid)

    run_ids.sort(key=sort_key, reverse=True)

    summaries = {}
    for sid in run_ids:
        summaries[sid] = summarize_run(os.path.join(reports_dir, sid + ".json"))

    scheduled = [s for s in run_ids if run_kind(s) == "scheduled"]
    releases = [s for s in run_ids if run_kind(s) == "release"]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    body = [
        "<h1>RKE2 VexScan Reports</h1>",
        '<p class="page-sub">Daily vexscan triage of the container images RKE2 ships. '
        "%d runs.</p>" % len(run_ids),
    ]
    if run_ids:
        body.append(
            '<div class="filter-bar">'
            '<input type="search" placeholder="Filter reports by date, name or type…" '
            'oninput="filterReports(this)" aria-label="Filter reports"></div>'
        )
        body.append(render_section("Scheduled scans", scheduled, summaries))
        body.append(render_section("Release scans", releases, summaries))
    else:
        body.append('<p class="empty-state">No reports yet. The first scheduled scan '
                     "will populate this page.</p>")

    body.append('<div class="page-footer">Generated %s · '
                'reports rendered by contrib/vexscan-dashboard.py</div>' % esc(now))

    html_doc = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RKE2 VexScan Reports</title>
<style>%s</style>
%s
</head>
<body>
<header class="page-header">
  <div class="brand">%s RKE2 VexScan</div>
  <span class="subtitle">— Vulnerability triage reports</span>
  %s
</header>
<main class="page-content">
%s
</main>
%s
</body>
</html>
""" % (CSS, THEME_HEAD, LOGO_SVG, THEME_TOGGLE, "\n".join(body), PAGE_SCRIPT)

    index_path = os.path.join(html_dir, "index.html")
    with open(index_path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    return index_path


def main():
    if len(sys.argv) != 2:
        print("Usage: %s <html-dir>" % sys.argv[0], file=sys.stderr)
        sys.exit(2)
    out = generate_index(sys.argv[1])
    print("Wrote %s" % out)


if __name__ == "__main__":
    main()
