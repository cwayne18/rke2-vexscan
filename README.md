# rke2-vexscan

Daily vulnerability triage of the container images that [RKE2](https://github.com/rancher/rke2)
ships, using [`vexscan`](https://github.com/cwayne18/vexscan) as the scan engine.

Unlike a plain version scanner, `vexscan` answers *is this CVE's vulnerable code
actually present, and can it actually run?* — running deterministic presence and
reachability tests per ecosystem and resolving published [VEX](https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex)
statements from [rancher/vexhub](https://github.com/rancher/vexhub). Findings are
bucketed into **affected**, **already vexed**, **undetermined** and **ruled out**.

By default the report is scoped to what is **actionable**: only **CRITICAL** and
**HIGH** findings, and only CVEs that have a **published fix**. Both are
adjustable (`--severity`, `--no-fixed-only`).

Reports are published to GitHub Pages, rendered from the raw vexscan JSON by the
upstream [`contrib/vexscan-dashboard.py`](https://github.com/cwayne18/vexscan/blob/main/contrib/vexscan-dashboard.py).

## How it works

- **`scan.sh`** builds the list of images RKE2 ships and runs `vexscan` over it,
  writing a JSON report.
  - *master / release branch*: reproduces the image list by running the upstream
    `scripts/build-images` in a sandbox (the same approach used by rke2-toolbox).
    The `rke2-runtime` image is scanned separately (see below), since in this
    mode its reference points at an unpublished dev tag that cannot be pulled.
  - *`--release <version>`*: hands `vexscan` the published `rke2-images` list URL
    from the GitHub release directly (which already includes `rke2-runtime`).
- **`.github/workflows/scan-report.yml`** runs the scan daily (and on demand),
  renders each run into `reports/html/<scan-id>/` with `vexscan-dashboard.py`,
  rebuilds the landing page, and commits the results.
- **`.github/scripts/generate_index.py`** builds `reports/html/index.html`, the
  landing page listing every run (styled after rke2-toolbox's index).
- **`.github/workflows/deploy-pages.yml`** publishes `reports/html/` to GitHub Pages.

### Scanning the `rke2-runtime` image

In branch mode, `build-images` tags the runtime image with a dev version that is
never pushed to a registry, so it cannot be pulled and scanned like the other
images. Instead `scan.sh`:

1. Drops the unpullable `rke2-runtime:` reference from the generated image list.
2. Finds the most recent completed `rancher/rke2` CI run for the branch that
   published a non-expired `rke2-test-artifacts` artifact (the real built runtime
   image, `rke2-images.linux-amd64.tar.zst`) and downloads it with `gh`.
3. Decompresses it and converts the docker-save tarball into an OCI layout with
   `skopeo` (vexscan reads registries or OCI layouts, not docker-save archives).
4. Scans the layout with `vexscan --haul` and merges those findings into the
   report so the runtime image is covered alongside everything else.

If any step fails (no artifact, missing `gh`/`skopeo`/`zstd`, etc.) the runtime
scan is skipped with a warning and the rest of the report is unaffected. In
`--release` mode this is unnecessary because the published `rke2-images` list
already includes the runtime image. Requires `gh` (authenticated), `skopeo` and
`zstd` on `PATH`; disable with `--no-runtime`.

## Running locally

Install the scan engine and fetch the dashboard renderer:

```sh
go install github.com/cwayne18/vexscan@latest
curl -fsSL https://raw.githubusercontent.com/cwayne18/vexscan/main/contrib/vexscan-dashboard.py -o vexscan-dashboard.py
```

Scan master (built from source) and render it:

```sh
./scan.sh master --prime --output scan.json
python3 vexscan-dashboard.py scan.json -o reports/html/scan-local/
python3 .github/scripts/generate_index.py reports/html
```

Scan a published release:

```sh
./scan.sh --release v1.37.0+rke2r1 --output rke2-1.37.0.json
```

### `scan.sh` options

```
Usage: scan.sh [branch] [--release <version>] [--prime] [--no-prime]
               [--vexhub <url>] [--prefer-vendor <vendor>] [--severity <list>]
               [--fixed-only] [--no-fixed-only] [--runtime] [--no-runtime]
               [--output <file>]
```

- `branch` — build the image list from this RKE2 branch (default `master`).
- `--release <version>` — scan a published release tag (`v1.37.0+rke2r1` or
  `v1.37.0-rke2r1`) straight from its `rke2-images` list.
- `--prime` / `--no-prime` — rewrite images to the prime registry
  (`registry.rancher.com`) and use the PRIME/hardened image variants. Scheduled
  scans use `--prime`.
- `--vexhub <url>` — VEX hub to resolve statements from (default
  `https://github.com/rancher/vexhub`).
- `--prefer-vendor <vendor>` — preferred VEX vendor (default `suse`).
- `--severity <list>` — comma-separated severities to report (default
  `CRITICAL,HIGH`). Pass `--severity ''` to report every severity.
- `--fixed-only` / `--no-fixed-only` — keep only CVEs that have a published fix.
  On by default; `--no-fixed-only` includes findings with no fix yet.
- `--runtime` / `--no-runtime` — in branch mode, also scan the `rke2-runtime`
  image from a `rancher/rke2` CI artifact (see above). On by default; ignored in
  `--release` mode where the runtime image is already in the published list.
- `--output <file>` — JSON output path (default `scan.json`).

## License

MIT — see [LICENSE](LICENSE).
