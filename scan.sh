#!/bin/bash

# Scan RKE2's shipped container images with vexscan (github.com/cwayne18/vexscan)
# and emit a JSON report. Two modes:
#
#   * branch (default "master"): reproduce the image list by cloning the ref
#     and running the upstream scripts/build-images against it, then scan
#     that list.
#   * --release <version>: scan the published rke2-images list straight from the
#     GitHub release, handing vexscan the URL directly.
#
# In both modes, ./gen-rke2-vexscan turns the bare image list into a fleet list
# (entrypoint=/roots= assertions saying how RKE2 actually starts each image,
# not just what its own config declares) before handing it to vexscan. If
# python3, PyYAML or helm are missing, or generation fails for any reason, the
# scan falls back to the bare image list with a warning rather than aborting.
#
# With --source-xref, it also asks ./gen-rke2-vexscan which upstream Go module
# + pinned ref actually backs each stripped component binary that is a go.mod
# dependency of rke2 (kube-apiserver/kubelet, etcd, containerd, crictl), runs
# vexscan in source mode (--repo/--ref) against each one, and feeds the
# resulting "ruled out" VEX statements back into the real image scan as an
# extra --vexhub. This is what lets a finding like "the vulnerable function is
# linked but never called" actually resolve on an image whose binaries are all
# stripped -- the pclntab test vexscan otherwise falls back to only sees
# package presence, not reachability. Off by default: a source-mode
# govulncheck run against the whole kubernetes module downloads the module
# graph and can need several GB of RAM.
#
# vexscan does its own triage and VEX resolution, so the output JSON is fed to
# contrib/vexscan-dashboard.py to render the HTML pages.

set -o pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

output_file="scan.json"
branch=""
use_prime_ingress="false"
prime_explicit=""
vexhub="https://github.com/rancher/vexhub"
prefer_vendor="suse"
severity_filter="CRITICAL,HIGH"
fixed_only="true"
scan_runtime_image="true"
source_xref="false"
# Registry used to reproduce PRIME builds. build-images emits the PRIME/hardened
# image variants only when REGISTRY != docker.io; the final scan targets
# registry.rancher.com.
prime_registry="registry.rancher.com"
release_version=""

usage() {
    echo "Usage: $0 [branch] [--release <version>] [--prime] [--no-prime]"
    echo "          [--vexhub <url>] [--prefer-vendor <vendor>] [--severity <list>]"
    echo "          [--fixed-only] [--no-fixed-only] [--runtime] [--no-runtime]"
    echo "          [--source-xref] [--no-source-xref] [--output <file>]"
    echo ""
    echo "Examples:"
    echo "  $0                         # scan master (built from source)"
    echo "  $0 release-1.35            # scan a release branch built from source"
    echo "  $0 --release v1.37.0+rke2r1"
    echo "  $0 --release v1.37.0-rke2r1"
    echo "  $0 --prime                 # rewrite images to the prime registry"
    echo "  $0 --severity ''           # report every severity (default: CRITICAL,HIGH)"
    echo "  $0 --no-fixed-only         # include CVEs with no fix (default: fixed only)"
    echo "  $0 --no-runtime            # skip the rke2-runtime image tarball scan"
    echo "  $0 --source-xref           # also cross-reference stripped Go binaries"
    echo "                             # against their upstream source in source mode"
    echo "  $0 --output rke2-master.json"
    echo ""
    echo "By default the report is limited to CRITICAL/HIGH findings that have a fix."
    echo "In branch mode the rke2-runtime image is built from source and scanned"
    echo "(disable with --no-runtime)."
    echo "--source-xref runs an extra govulncheck source-mode scan per stripped"
    echo "component (kube-apiserver/kubelet, etcd, containerd, crictl) against its"
    echo "pinned upstream repo, to rule out findings the stripped-binary pclntab"
    echo "test can only call 'linked'. Off by default: expensive (downloads the"
    echo "kubernetes module graph) and not needed for most scans."
    echo "Note: scheduled scans run '$0 master --prime'."
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--release)
            if [[ -z "$2" ]]; then
                echo "Error: --release requires a version value"
                usage
                exit 1
            fi
            release_version="$2"
            shift 2
            ;;
        --prime)
            use_prime_ingress="true"
            prime_explicit="true"
            shift
            ;;
        --no-prime)
            use_prime_ingress="false"
            prime_explicit="true"
            shift
            ;;
        --runtime)
            scan_runtime_image="true"
            shift
            ;;
        --no-runtime)
            scan_runtime_image="false"
            shift
            ;;
        --source-xref)
            source_xref="true"
            shift
            ;;
        --no-source-xref)
            source_xref="false"
            shift
            ;;
        --vexhub)
            if [[ -z "$2" ]]; then
                echo "Error: --vexhub requires a URL value"
                usage
                exit 1
            fi
            vexhub="$2"
            shift 2
            ;;
        --prefer-vendor)
            if [[ -z "$2" ]]; then
                echo "Error: --prefer-vendor requires a value"
                usage
                exit 1
            fi
            prefer_vendor="$2"
            shift 2
            ;;
        --severity)
            # Empty string is allowed and means "all severities".
            severity_filter="$2"
            shift 2
            ;;
        --fixed-only)
            fixed_only="true"
            shift
            ;;
        --no-fixed-only)
            fixed_only="false"
            shift
            ;;
        -o|--output)
            if [[ -z "$2" ]]; then
                echo "Error: --output requires a file value"
                usage
                exit 1
            fi
            output_file="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            # Backward-compatible positional branch argument.
            if [[ -z "$branch" ]]; then
                branch="$1"
                shift
            else
                echo "Error: Unknown argument '$1'"
                usage
                exit 1
            fi
            ;;
    esac
done

if [[ -z "$branch" ]]; then
    branch="master"
fi

if [[ -n "$release_version" ]]; then
    # Normalize release version: convert "-rke2rN" suffix to "+rke2rN" so the
    # tag matches GitHub's release naming. URL-encode the '+' as '%2B'.
    release_tag="$release_version"
    if [[ "$release_tag" =~ ^(.*)-rke2r([0-9]+)$ ]]; then
        release_tag="${BASH_REMATCH[1]}+rke2r${BASH_REMATCH[2]}"
    fi
    release_tag_url="${release_tag//+/%2B}"
    source_desc="release ${release_tag}"
else
    ref_path="refs/heads/${branch}"
    source_desc="branch '${branch}'"
fi

if ! command -v vexscan >/dev/null 2>&1; then
    echo "Error: vexscan CLI not found in PATH." >&2
    echo "       Install with: go install github.com/cwayne18/vexscan@latest" >&2
    exit 1
fi

# Runtime image scanning state. In build-from-source mode the rke2-runtime
# reference generated by build-images points at a dev tag that is never pushed
# to a registry, so it cannot be pulled. Instead we build the real runtime
# image from source and scan that (see build_runtime_image).
runtime_layout=""
runtime_ref=""
runtime_source_desc=""
runtime_source_url=""
runtime_expected_tag=""
runtime_commit=""

# runtime_repo_tag prints the first RepoTag recorded in a docker-save tarball,
# so the report can name the runtime image the way build-images tagged it.
runtime_repo_tag() {
    local tar_path="$1"
    tar -xOf "$tar_path" manifest.json 2>/dev/null | python3 -c '
import json, sys
try:
    manifest = json.load(sys.stdin)
    tags = (manifest[0] or {}).get("RepoTags") or []
    print(tags[0] if tags else "")
except Exception:
    print("")
' 2>/dev/null
}

# tag_component prints the version tag portion (after the last ':') of an image
# ref, so the expected ref from images.txt and the RepoTag read back out of the
# built tarball can be compared by version alone regardless of
# registry/namespace differences.
tag_component() {
    local ref="$1"
    echo "${ref##*:}"
}

# build_runtime_image builds the real rke2-runtime image from the rancher/rke2
# checkout at $1 using the upstream scripts/build-image-runtime, then converts
# the resulting docker-save tarball into an OCI layout vexscan can scan with
# --haul (vexscan reads a registry or an OCI layout, not a docker-save
# archive). $2 is the unpullable rke2-runtime: reference images.txt produced
# for this same checkout, used only to sanity-check the build's own version
# against it. On success this sets runtime_layout, runtime_ref and the
# runtime_source_* metadata; on any problem (missing docker/buildx/skopeo, a
# build failure, ...) it warns and leaves runtime_layout empty so the rest of
# the scan proceeds unaffected.
build_runtime_image() {
    local clone_dir="$1"
    local expected_tag="$2"
    local desc="branch '${branch}'"

    if [[ -n "$expected_tag" ]]; then
        runtime_expected_tag="$expected_tag"
    fi

    if ! command -v docker >/dev/null 2>&1; then
        echo "Warning: docker not found; skipping runtime image scan"
        return 1
    fi
    if ! docker buildx version >/dev/null 2>&1; then
        echo "Warning: docker buildx not available; skipping runtime image scan"
        return 1
    fi
    if ! command -v skopeo >/dev/null 2>&1; then
        echo "Warning: skopeo not found; skipping runtime image scan"
        return 1
    fi

    echo "Building rke2-runtime image from source for ${desc}..."
    local build_log="$work_dir/build-image-runtime.log"
    # SKIP_WINDOWS skips the extra windows-runtime build; we only scan linux.
    # GOARCH/GOOS match the same arch run_build_images resolved the rest of
    # the image list for.
    if ! (
        cd "$clone_dir" \
        && export GOARCH="${GOARCH:-$(go env GOARCH)}" \
        && export GOOS="${GOOS:-$(go env GOOS)}" \
        && export SKIP_WINDOWS=1 \
        && bash scripts/build-image-runtime
    ) >"$build_log" 2>&1; then
        echo "Warning: building rke2-runtime image failed; skipping runtime image scan"
        tail -n 40 "$build_log" >&2
        return 1
    fi

    local tar_path
    tar_path=$(find "$clone_dir/build/images" -maxdepth 1 -type f -name 'rke2-images.*.tar' 2>/dev/null | head -1)
    if [[ -z "$tar_path" ]]; then
        echo "Warning: rke2-runtime build produced no image tarball; skipping runtime image scan"
        return 1
    fi

    local repo_tag
    repo_tag=$(runtime_repo_tag "$tar_path")
    [[ -z "$repo_tag" ]] && repo_tag="rancher/rke2-runtime:${expected_tag##*:}"

    if [[ -n "$expected_tag" && "$(tag_component "$repo_tag")" != "$(tag_component "$expected_tag")" ]]; then
        echo "Warning: built rke2-runtime image is $(tag_component "$repo_tag"), not the expected $(tag_component "$expected_tag") for ${desc}; scanning it anyway"
    fi

    runtime_ref="$repo_tag"

    local layout_dir="$work_dir/runtime-oci"
    rm -rf "$layout_dir"
    mkdir -p "$layout_dir"
    echo "Converting runtime image to an OCI layout (${repo_tag})..."
    if ! skopeo copy "docker-archive:${tar_path}" "oci:${layout_dir}:${repo_tag}" >/dev/null 2>&1; then
        echo "Warning: failed to convert built runtime image to an OCI layout; skipping runtime image scan"
        return 1
    fi

    local commit_sha
    commit_sha=$(git -C "$clone_dir" rev-parse HEAD 2>/dev/null)

    runtime_layout="$layout_dir"
    runtime_source_url="https://github.com/rancher/rke2/commit/${commit_sha}"
    runtime_source_desc="built from rancher/rke2 ${desc} (commit ${commit_sha:0:8})"
    runtime_commit="$commit_sha"
    echo "Runtime image ready to scan: ${repo_tag}"
    return 0
}

# generate_fleet_list runs ./gen-rke2-vexscan for $1 (a release tag or branch)
# against the image list already on disk at $2, or against the release's own
# --lists $3 when $2 is empty, and prints the fleet-list path on success.
# On any failure -- missing python3/PyYAML/helm, network trouble, a chart
# that won't render, whatever -- it warns on stderr and returns non-zero, so
# the caller falls back to scanning the bare image list instead of aborting.
generate_fleet_list() {
    local ref="$1" images_file="$2" lists="$3" out="fleet.txt"

    if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import yaml' >/dev/null 2>&1; then
        echo "Note: python3/PyYAML not available; scanning without entrypoint=/roots= assertions" >&2
        return 1
    fi
    if ! command -v helm >/dev/null 2>&1; then
        echo "Note: helm not found; scanning without entrypoint=/roots= assertions" >&2
        return 1
    fi

    echo "Generating a fleet list (how RKE2 starts each image) for ${ref}..." >&2
    local gen_log gen_args=("$ref" -o "$out")
    if [[ -n "$images_file" ]]; then
        gen_args+=(--images-from "$images_file")
    else
        gen_args+=(--lists "$lists")
    fi
    gen_log=$(mktemp)
    if "$script_dir/gen-rke2-vexscan" "${gen_args[@]}" 2>"$gen_log"; then
        rm -f "$gen_log"
        echo "$out"
        return 0
    fi
    echo "Warning: gen-rke2-vexscan failed; scanning without entrypoint=/roots= assertions" >&2
    cat "$gen_log" >&2
    rm -f "$gen_log"
    return 1
}

# prime_rewrite_fleet_list applies the same docker.io -> registry.rancher.com
# rewrite as images.txt's, but only to the leading image-ref token of each
# fleet-list line -- comments and entrypoint=/cmd=/roots= assertions are left
# untouched, unlike images.txt where the whole line is a bare ref.
prime_rewrite_fleet_list() {
    python3 - "$1" <<'PY'
import re
import sys

path = sys.argv[1]


def rewrite(ref):
    if ref.startswith("docker.io/"):
        ref = "registry.rancher.com/" + ref[len("docker.io/"):]
    first = ref.split("/", 1)[0]
    if not re.search(r"[.:]", first):
        ref = "registry.rancher.com/" + ref
    return ref


with open(path, encoding="utf-8") as fh:
    lines = fh.read().split("\n")

out = []
for line in lines:
    if line == "" or line.startswith("#"):
        out.append(line)
        continue
    parts = line.split(None, 1)
    ref = rewrite(parts[0])
    out.append(ref if len(parts) == 1 else f"{ref} {parts[1]}")

with open(path, "w", encoding="utf-8") as fh:
    fh.write("\n".join(out))
PY
}

# generate_source_vex runs ./gen-rke2-vexscan --source-refs for $1 (a release
# tag or branch) to resolve the upstream repo+ref backing each stripped
# component binary that is a go.mod dependency of rke2, then runs vexscan in
# source mode (--repo/--ref/--repo-path) against each one, writing every
# finding it rules out as a VEX statement into $2 (a directory). Prints $2 on
# success (at least one component produced a statement) and returns non-zero
# on any other outcome. Same resilience pattern as generate_fleet_list: a
# missing python3/PyYAML, network trouble, or a govulncheck failure on any one
# component warns on stderr and is skipped rather than aborting the scan.
source_vex_author="rke2-vexscan source cross-reference (ephemeral, not published)"

generate_source_vex() {
    local ref="$1" out_dir="$2" refs_file="source-refs.txt"

    if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import yaml' >/dev/null 2>&1; then
        echo "Note: python3/PyYAML not available; skipping source cross-reference" >&2
        return 1
    fi

    echo "Resolving upstream source refs for stripped components at ${ref}..." >&2
    local gen_log
    gen_log=$(mktemp)
    if ! "$script_dir/gen-rke2-vexscan" "$ref" --source-refs "$refs_file" 2>"$gen_log"; then
        echo "Warning: gen-rke2-vexscan --source-refs failed; skipping source cross-reference" >&2
        cat "$gen_log" >&2
        rm -f "$gen_log"
        return 1
    fi
    cat "$gen_log" >&2
    rm -f "$gen_log"

    mkdir -p "$out_dir"
    local wrote="false" component repo comp_ref repo_path xref_log
    while read -r component repo comp_ref repo_path; do
        [[ -z "$component" || "$component" == \#* ]] && continue
        echo "Source-mode scanning ${component} (${repo}@${comp_ref})..." >&2
        local xref_args=(
            --repo "$repo" --ref "$comp_ref"
            --all --ecosystem golang
            --vex-out "$out_dir" --vex-author "$source_vex_author"
            --format json
        )
        [[ "$repo_path" != "." ]] && xref_args+=(--repo-path "$repo_path")
        xref_log=$(mktemp)
        if vexscan "${xref_args[@]}" >/dev/null 2>"$xref_log"; then
            wrote="true"
        else
            echo "Warning: source-mode scan of ${component} failed; skipping" >&2
            cat "$xref_log" >&2
        fi
        rm -f "$xref_log"
    done < "$refs_file"
    rm -f "$refs_file"

    if [[ "$wrote" == "true" ]]; then
        echo "$out_dir"
        return 0
    fi
    return 1
}

rm -f "$output_file" fleet.txt source-refs.txt
rm -rf source-vex
rm -f images.txt

# vexscan's --images-from accepts a URL or a file. In release mode we hand it
# the release URL untouched unless a fleet list can be generated for it; in
# branch mode we build a local images.txt (and try to build a fleet list too).
images_source=""

echo "Scanning using ${source_desc}"

if [[ -n "$release_version" ]]; then
    # Release mode: point vexscan straight at the published images list.
    images_source="https://github.com/rancher/rke2/releases/download/${release_tag_url}/rke2-images.linux-amd64.txt"
    echo "Using release images list: $images_source"

    # gen-rke2-vexscan's default --lists is "default,ingress-nginx"; restrict
    # it to "default" here so the fleet list covers exactly the one image list
    # this mode actually scans.
    fleet_list=""
    if fleet_list=$(generate_fleet_list "$release_tag" "" "default"); then
        images_source="./${fleet_list}"
    fi
else
    # Build-from-source mode: clone the ref and run the upstream build-images
    # script against the real checkout, collecting the generated image lists
    # into a single images.txt. A real checkout (rather than just the two
    # scripts) is what lets version.sh compute a real commit-based version,
    # which build_runtime_image below relies on to build the real
    # rke2-runtime image for this exact ref.
    work_dir=$(mktemp -d)
    cleanup() {
        rm -rf "$work_dir"
    }
    trap cleanup EXIT

    mkdir -p "$work_dir/build"

    raw_repo="rancher/rke2"
    clone_dir="$work_dir/rke2"

    echo "Cloning rancher/rke2 (${ref_path}) to reproduce its build..."
    if ! git clone --quiet --depth 1 --branch "$branch" \
        "https://github.com/${raw_repo}.git" "$clone_dir" 2>"$work_dir/clone.log"; then
        cat "$work_dir/clone.log" >&2
        echo "Error: failed to clone ${raw_repo} at ${source_desc}"
        exit 1
    fi

    if [[ "$use_prime_ingress" == "true" ]]; then
        ingress_nginx_hardened_tag=$(sed -n 's/^INGRESS_NGINX_HARDENED_TAG=//p' "$clone_dir/scripts/build-images" | head -n 1)
        ingress_nginx_prime_tag=$(sed -n 's/^INGRESS_NGINX_PRIME_TAG=//p' "$clone_dir/scripts/build-images" | head -n 1)

        if [[ -z "$ingress_nginx_hardened_tag" || -z "$ingress_nginx_prime_tag" ]]; then
            echo "Error: failed to determine ingress-nginx hardened/prime tags from build-images"
            exit 1
        fi
    fi

    # Run scripts/build-images with scan-specific controls. Image lists are
    # generated without pulling anything (PULL_CMD stubbed) and without building
    # the runtime image here (build_runtime_image does that separately once the
    # rest of the image list is known).
    run_build_images() {
        local out_dir="$1"
        local registry_override="$2"
        (
            export GOARCH="${GOARCH:-$(go env GOARCH)}"
            export GOOS="${GOOS:-$(go env GOOS)}"
            export BUILD_DIR="$out_dir"
            export SKIP_BUILD_IMAGE_RUNTIME=1
            export PULL_CMD=echo
            export PULL_CMD_CORE=echo
            [[ -n "$registry_override" ]] && export REGISTRY="$registry_override"
            bash "$clone_dir/scripts/build-images"
        )
    }

    if ! run_build_images "$work_dir/build" "" \
        > /dev/null 2> "$work_dir/build-images.log"; then
        cat "$work_dir/build-images.log"
        exit 1
    fi

    if [[ "$use_prime_ingress" == "true" ]]; then
        ingress_images_file="$work_dir/build/images-ingress-nginx.txt"

        if [[ ! -f "$ingress_images_file" ]]; then
            echo "Error: expected ingress-nginx image list was not generated"
            exit 1
        fi

        sed -i.bak "s/:${ingress_nginx_hardened_tag}$/:${ingress_nginx_prime_tag}/" "$ingress_images_file"
        rm -f "${ingress_images_file}.bak"

        # PRIME-only hardened vsphere images are emitted only when
        # REGISTRY != docker.io. Regenerate just the vsphere list against the
        # prime registry and swap it in so the scan reflects the hardened images
        # shipped in PRIME builds.
        prime_build_dir="$work_dir/build-prime"
        mkdir -p "$prime_build_dir"
        if ! run_build_images "$prime_build_dir" "$prime_registry" \
            > /dev/null 2> "$work_dir/build-images-prime.log"; then
            cat "$work_dir/build-images-prime.log"
            exit 1
        fi
        if [[ -f "$prime_build_dir/images-vsphere.txt" ]]; then
            cp "$prime_build_dir/images-vsphere.txt" "$work_dir/build/images-vsphere.txt"
        fi
    fi

    # Full image list: every generated list, de-duplicated. The historical
    # "mirrored-" passthrough entries are dropped so the scan reflects the
    # images RKE2 actually ships.
    find "$work_dir/build" -maxdepth 1 -type f -name 'images-*.txt' -print0 \
        | xargs -0 cat \
        | grep -vE 'mirrored' \
        | awk 'NF && !seen[$0]++' \
        > images.txt

    if [[ ! -s images.txt ]]; then
        echo "Error: no images were generated for ${source_desc}"
        exit 1
    fi

    # In build-from-source mode the rke2-runtime reference points at a dev tag
    # that is never pushed to a registry, so a registry scan of it always fails.
    # Capture it before dropping it (before any registry rewrite, which doesn't
    # change whether a line matches): it's the version build-images produced
    # for this exact ref, and build_runtime_image uses it below as a sanity
    # check against the version it actually builds from the same checkout.
    expected_runtime_tag=$(grep -E '(^|/)rke2-runtime:' images.txt | head -1)
    sed -i.bak '/\/rke2-runtime:/d; /^rke2-runtime:/d' images.txt
    rm -f images.txt.bak

    echo "Built image list with $(wc -l < images.txt | tr -d ' ') images"

    # Try to generate a fleet list before any --prime rewrite: gen-rke2-vexscan
    # resolves entrypoints/roots by pulling each image from its home registry
    # (docker.io), which the prime-rewritten refs below no longer point at.
    fleet_list=$(generate_fleet_list "$branch" images.txt "") || fleet_list=""

    # When --prime is set, rewrite image references to registry.rancher.com
    # instead of docker.io (or an implicit docker.io with no registry prefix).
    if [[ "$use_prime_ingress" == "true" ]]; then
        awk '
            {
                line = $0
                if (line == "") { print; next }
                sub(/^docker\.io\//, "registry.rancher.com/", line)
                n = index(line, "/")
                first = (n > 0) ? substr(line, 1, n - 1) : line
                if (first !~ /[.:]/) {
                    line = "registry.rancher.com/" line
                }
                print line
            }
        ' images.txt > images.txt.tmp && mv images.txt.tmp images.txt

        if [[ -n "$fleet_list" ]]; then
            prime_rewrite_fleet_list "$fleet_list"
        fi
    fi

    images_source="./images.txt"
    if [[ -n "$fleet_list" ]]; then
        images_source="./${fleet_list}"
    fi

    if [[ "$scan_runtime_image" == "true" ]]; then
        build_runtime_image "$clone_dir" "$expected_runtime_tag"
    else
        echo "Skipping runtime image scan (--no-runtime)"
    fi
fi

source_vexhub=""
if [[ "$source_xref" == "true" ]]; then
    source_vexhub=$(generate_source_vex "${release_tag:-$branch}" "source-vex") || source_vexhub=""
else
    echo "Skipping source cross-reference (--source-xref not set)"
fi

echo "Running vexscan (vexhub=${vexhub}, prefer-vendor=${prefer_vendor}, severity=${severity_filter:-all})..."
vexscan_args=(
    --images-from "$images_source"
    --all --triage
    --vexhub "$vexhub"
)
if [[ -n "$source_vexhub" ]]; then
    vexscan_args+=(--vexhub "$source_vexhub")
fi
vexscan_args+=(--prefer-vendor "$prefer_vendor")
if [[ -n "$severity_filter" ]]; then
    vexscan_args+=(--severity "$severity_filter")
fi
vexscan_args+=(--format json)

vexscan "${vexscan_args[@]}" > "$output_file"

if [[ ! -s "$output_file" ]]; then
    echo "Error: vexscan produced no output"
    exit 1
fi

# Scan the runtime image tarball (converted to an OCI layout above) and merge
# its results into the report so the rke2-runtime image is covered even though
# its build-from-source reference is not pullable from a registry.
if [[ -n "$runtime_layout" ]]; then
    echo "Scanning runtime image from ${runtime_source_desc}..."
    runtime_output="runtime-scan.json"
    rm -f "$runtime_output"
    runtime_args=(
        --haul "$runtime_layout"
        --all --triage
        --vexhub "$vexhub"
    )
    if [[ -n "$source_vexhub" ]]; then
        runtime_args+=(--vexhub "$source_vexhub")
    fi
    runtime_args+=(--prefer-vendor "$prefer_vendor")
    if [[ -n "$severity_filter" ]]; then
        runtime_args+=(--severity "$severity_filter")
    fi
    runtime_args+=(--format json)

    if vexscan "${runtime_args[@]}" > "$runtime_output" && [[ -s "$runtime_output" ]]; then
        python3 - "$output_file" "$runtime_output" \
            "$runtime_source_url" "$runtime_commit" \
            "$runtime_expected_tag" "$runtime_ref" <<'PY'
import json
import sys

main_path, runtime_path, commit_url, commit_sha, expected_tag, actual_tag = sys.argv[1:7]
with open(main_path, encoding="utf-8") as fh:
    main = json.load(fh)
with open(runtime_path, encoding="utf-8") as fh:
    runtime = json.load(fh)

main.setdefault("results", [])
main.setdefault("failures", [])
main["results"].extend(runtime.get("results") or [])
main["failures"].extend(runtime.get("failures") or [])
if isinstance(main.get("targets"), int):
    main["targets"] = len(main["results"]) + len(main["failures"])

# Record the commit the runtime image was built from and whether its version
# matched what was expected for this branch, so a mismatch is auditable from
# the report itself instead of only from scan.sh's console output.
main["runtime_image_source"] = {
    "method": "built-from-source",
    "commit_url": commit_url or None,
    "commit": commit_sha or None,
    "expected_tag": expected_tag or None,
    "actual_tag": actual_tag or None,
    "version_matched": (not expected_tag) or (expected_tag.rsplit(":", 1)[-1] == actual_tag.rsplit(":", 1)[-1]),
}

with open(main_path, "w", encoding="utf-8") as fh:
    json.dump(main, fh)
PY
        echo "Merged runtime image findings into ${output_file}"
    else
        echo "Warning: runtime image scan produced no output; report will not include the runtime image"
    fi
    rm -f "$runtime_output"
fi

# vexscan has no "fixed only" flag, so drop findings with no published fix here.
# A finding is fixable when it carries a fixed_version (or fixed_versions list).
if [[ "$fixed_only" == "true" ]]; then
    echo "Filtering report to findings with a published fix..."
    python3 - "$output_file" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    doc = json.load(fh)


def has_fix(finding):
    if finding.get("fixed_version"):
        return True
    return bool(finding.get("fixed_versions"))


def filter_result(result):
    findings = result.get("findings") or []
    result["findings"] = [f for f in findings if has_fix(f)]


if isinstance(doc.get("results"), list):
    for result in doc["results"]:
        if result:
            filter_result(result)
elif "findings" in doc:
    filter_result(doc)

with open(path, "w", encoding="utf-8") as fh:
    json.dump(doc, fh)
PY
fi

echo "Wrote scan report to ${output_file}"
