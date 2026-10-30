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
  writing a JSON report. In both modes it first tries `./gen-rke2-vexscan` to
  turn the bare list into a *fleet list* (see below) before handing it to
  `vexscan --images-from`; if that fails for any reason (missing `python3`,
  `PyYAML` or `helm`, a network hiccup, ...) it warns and falls back to the
  bare list rather than aborting the scan.
  - *master / release branch*: reproduces the image list by running the upstream
    `scripts/build-images` in a sandbox (the same approach used by rke2-toolbox).
    The `rke2-runtime` image is scanned separately (see below), since in this
    mode its reference points at an unpublished dev tag that cannot be pulled.
  - *`--release <version>`*: hands `vexscan` the published `rke2-images` list URL
    from the GitHub release directly (which already includes `rke2-runtime`),
    unless a fleet list generated from that same release replaces it.
  With `--source-xref` it additionally cross-references stripped Go component
  binaries against their upstream source (see below) before the main scan.
- **`.github/workflows/scan-report.yml`** runs the scan daily (and on demand),
  renders each run into `reports/html/<scan-id>/` with `vexscan-dashboard.py`,
  rebuilds the landing page, and commits the results.
- **`.github/scripts/generate_index.py`** builds `reports/html/index.html`, the
  landing page listing every run (styled after rke2-toolbox's index).
- **`.github/workflows/deploy-pages.yml`** publishes `reports/html/` to GitHub Pages.
- **`gen-rke2-vexscan`** builds a *fleet list* for a release or branch — the
  image list plus, per image, how RKE2 actually starts it. `scan.sh` runs it
  automatically. See below.

## `gen-rke2-vexscan` — saying how each image is started

`scan.sh` hands vexscan a bare list of image references, so every image is
scanned as if its own `ENTRYPOINT` is what runs. For most of RKE2's images that
is wrong, and wrong in the direction that costs you answers:

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

For a branch or commit that has never been released — no GitHub release
assets, no pushed `rke2-runtime` image — pass the image list `scan.sh` already
built instead:

```sh
./gen-rke2-vexscan master --images-from images.txt -o fleet.txt
vexscan --images-from fleet.txt --all --ecosystem os
```

Four sources, all pinned to the ref you name and all checkable:

- the **image list**, from the release's `rke2-images*.linux-amd64.txt`, or
  from `--images-from` for a ref with no release;
- the **addons**, from `charts/chart_versions.yaml` at that ref, fetched from
  the exact pinned `https://rke2-charts.rancher.io/assets/<package>/<name>-
  <version>.tgz` URL `scripts/build-chart.sh` builds them from — so this needs
  no pushed `rke2-runtime` image and works the same for a branch as a tag;
- the **static pods**, from `pkg/podtemplate/spec.go` and `pkg/images/images.go`
  at the ref, which is where `kube-apiserver`, `etcd` and friends get their
  (bare) command names;
- the **paths**, from the image layers, because a bare `etcd` has to be resolved
  against a `PATH` a fleet list cannot see.

It only names charts this image list actually deploys. `chart_versions.yaml`
pins every chart RKE2 *can* install, including three mutually exclusive CNIs; a
chart whose images are not in the selected lists is not this cluster's chart
and contributes nothing. That is why `hardened-flannel` gets canal's command
and not a union of canal's and standalone-flannel's.

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
Usage: gen-rke2-vexscan <tag> [-o FILE] [--images-from FILE]
                              [--lists default,ingress-nginx]
                              [--chart-repo URL] [--cache DIR] [--no-cache]
                              [--source-refs FILE]
```

`--lists` selects which of the release's image lists to cover (ignored when
`--images-from` is given). The default is `default,ingress-nginx`, matching a
default install with the bundled ingress.

`--source-refs FILE` is a separate, independent action (no `helm` required):
it resolves the upstream source repo+ref backing each stripped Go component
binary and writes them to `FILE` instead of building a fleet list. See
[Cross-referencing stripped binaries against source](#cross-referencing-stripped-binaries-against-source---source-xref)
below.

### Scanning the `rke2-runtime` image

In branch mode, `build-images` tags the runtime image with a dev version that is
never pushed to a registry, so it cannot be pulled and scanned like the other
images. Instead `scan.sh`:

1. Captures the unpullable `rke2-runtime:` reference from the generated image
   list as the expected version, then drops it (it can't be scanned directly).
2. Clones the branch and runs the upstream `scripts/build-image-runtime`
   against that real checkout with `docker buildx`, building the actual
   `rke2-runtime` image for that exact commit (the same build the branch's own
   CI would produce).
3. Reads the built image's own `RepoTag` back and checks it against the
   expected version from step 1, warning (but still scanning) on a mismatch.
4. Converts the built docker-save tarball into an OCI layout with `skopeo`
   (vexscan reads registries or OCI layouts, not docker-save archives).
5. Scans the layout with `vexscan --haul` and merges those findings into the
   report so the runtime image is covered alongside everything else. The
   commit it was built from, and the expected/actual version, are recorded in
   the report's `runtime_image_source` field for auditing.

If any step fails (clone, build, missing `docker`/`skopeo`, etc.) the runtime
scan is skipped with a warning and the rest of the report is unaffected. In
`--release` mode this is unnecessary because the published `rke2-images` list
already includes the runtime image. Requires `git`, `docker` (with `buildx`)
and `skopeo` on `PATH`; disable with `--no-runtime`.

### Cross-referencing stripped binaries against source (`--source-xref`)

Every stripped Go binary RKE2 ships — `kube-apiserver`, `kubelet`,
`kube-scheduler`, `kube-controller-manager`, `kube-proxy`, `etcd`,
`containerd` and `crictl` are all built with `install -s` or an explicit
`strip` — loses the symbol table govulncheck's binary-mode reachability test
needs, so `vexscan` can only run its coarser pclntab test against them: *is
any symbol from the vulnerable package linked at all*, not *is the specific
vulnerable function reachable*. A finding like "the vulnerable function is
linked but genuinely never called" stays reported as `linked` forever on
these images, because the sharper test never runs.

`vexscan --repo/--ref` sidesteps stripping entirely: it runs govulncheck in
**source mode** against a git ref, where call-graph reachability is computed
straight from source and does not depend on what a build strips. `--source-xref`
runs that, once per component, against the exact upstream commit RKE2's own
`go.mod` pins for this ref — the same real build that produced the shipped
binary — and writes every finding it rules out as VEX statements via
`--vex-out`, which the main scan then layers in as an extra `--vexhub`
alongside `rancher/vexhub`. Nothing about how the main scan is computed
changes; this only fills in verdicts the pclntab test could not reach on its
own.

Resolution is `./gen-rke2-vexscan <ref> --source-refs FILE`: it reads
`go.mod`'s `replace` directives for the four components that are actual
`go.mod` dependencies of `rancher/rke2` — `k8s.io/kubernetes` (covers all five
`kube-*` binaries), `go.etcd.io/etcd/server/v3`, `github.com/containerd/
containerd/v2` and `sigs.k8s.io/cri-tools` — and resolves each one to the
`k3s-io` fork + exact pinned tag the replace directive names, verifying the
module path at candidate subdirectories against the replacement's own `go.mod`
(so, e.g., etcd's `server/v3` replacement resolves to repo-path `server`, not
a literal `server/v3` directory, while containerd's `v2` is a pure
major-version suffix with no subdirectory at all). A component with no
replace line, a non-GitHub replacement, or an unverifiable path is skipped
with a warning rather than guessed at.

**Not covered**: `calico`, `coredns`, `metrics-server`, `runc` and
`rke2-cloud-provider` are not `go.mod` dependencies of `rke2` — their versions
only appear in their own `hardened-*`/`rke2-cloud-provider` image tags, which
would need a separate (and considerably more brittle) tag-parsing heuristic to
resolve back to an upstream repo+ref. Left as follow-up work.

**Caveat**: source-mode reachability is computed for the whole module (all of
`k8s.io/kubernetes`, say), not scoped to the single binary that image ships.
If some *other* command in the same module calls the vulnerable symbol, the
whole-module verdict is "reachable" and no VEX statement gets written — safe,
but coarser than a per-binary verdict would be.

`--source-xref` is off by default: a source-mode govulncheck run against the
whole `kubernetes` module downloads its module graph and builds it, which
`vexscan`'s own docs note can need several GB of RAM. The scheduled daily scan
(`.github/workflows/scan-report.yml`) enables it explicitly.

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
               [--source-xref] [--no-source-xref] [--output <file>]
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
- `--runtime` / `--no-runtime` — in branch mode, also build and scan the
  `rke2-runtime` image from source (see above). On by default; ignored in
  `--release` mode where the runtime image is already in the published list.
- `--source-xref` / `--no-source-xref` — also cross-reference stripped Go
  component binaries against their upstream source in govulncheck source mode
  (see above). Off by default: expensive, downloads the kubernetes module
  graph. The scheduled daily scan enables it.
- `--output <file>` — JSON output path (default `scan.json`).

## License

MIT — see [LICENSE](LICENSE).
