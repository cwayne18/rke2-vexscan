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
- **`gen-rke2-vexscan`** builds a *fleet list* for a release — the image list
  plus, per image, how RKE2 actually starts it. See below.

## `gen-rke2-vexscan` — saying how each image is started

`scan.sh --release` hands vexscan a bare list of image references, so every
image is scanned as if its own `ENTRYPOINT` is what runs. For most of RKE2's
images that is wrong, and wrong in the direction that costs you answers:

| image | its config says | RKE2 actually runs |
|---|---|---|
| `hardened-flannel` | `CMD ["/bin/sh"]` | `/opt/bin/flanneld --ip-masq …` |
| `hardened-etcd` | no ENTRYPOINT, no CMD | `etcd` |
| `hardened-kubernetes` | no ENTRYPOINT, no CMD | four static pods |
| `hardened-calico` | `CMD ["/bin/bash"]` | three canal containers |
| `rke2-runtime` | no ENTRYPOINT, no CMD | not a pod at all — `/bin/*` on the host |

vexscan roots its reachability closure on the command that runs, so an image
whose declared command is `/bin/sh` gets a shell-entrypoint taint and rules out
nothing. Telling it the truth is what `entrypoint=`, `cmd=` and `roots=` are for.

If you have the cluster, ask the cluster — it knows what you configured:

```sh
kubectl get pods -A -o yaml | vexscan --images-from - --all --ecosystem os
```

For a release you have not installed, there is nothing to ask, so this script
reconstructs the same facts from the release artifacts:

```sh
./gen-rke2-vexscan v1.37.1-rc1+rke2r1 -o rke2.txt
vexscan --images-from rke2.txt --all --ecosystem os
```

Four sources, all pinned to the tag you name and all checkable:

- the **image list**, from the release's `rke2-images*.linux-amd64.txt`;
- the **addons**, from `rancher/rke2-runtime:<tag>`, which ships every bundled
  Helm chart inline (base64 gzipped, in its `charts/*.yaml` HelmChart CRs), so
  the charts are exactly the build that release deploys — rendered with
  `helm template`, never fetched from a chart repo;
- the **static pods**, from `pkg/podtemplate/spec.go` and `pkg/images/images.go`
  at the tag, which is where `kube-apiserver`, `etcd` and friends get their
  (bare) command names;
- the **paths**, from the image layers, because a bare `etcd` has to be resolved
  against a `PATH` a fleet list cannot see.

It only names charts this image list actually deploys. The runtime image carries
every chart RKE2 *can* install, including three mutually exclusive CNIs; a chart
whose images are not in the selected lists is not this cluster's chart and
contributes nothing. That is why `hardened-flannel` gets canal's command and not
a union of canal's and standalone-flannel's.

Two things it will not do:

- **It never emits `exec-policy=`, `dlopen-policy=` or `dlopen-assume-none=`.**
  Saying which program starts is not saying that program starts nothing, and
  only someone who knows the workload can make the second claim. The generated
  file carries a commented block about that instead.
- **It never guesses a path.** A command it cannot resolve to a file that exists
  in the image is written as a comment with no assertion: an unresolvable
  `roots=` is a blocking taint in vexscan, and a *wrong* one that does resolve
  quietly narrows the closure.

Requirements: `python3` (stdlib + PyYAML) and `helm`. No Docker, no cluster.
Registry blobs are cached under `~/.cache/rke2-vexscan/<tag>/`; `--no-cache`
clears it first.

```
Usage: gen-rke2-vexscan <tag> [-o FILE] [--lists default,ingress-nginx]
                              [--cache DIR] [--no-cache]
```

`--lists` selects which of the release's image lists to cover. The default is
`default,ingress-nginx`, matching a default install with the bundled ingress.

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
