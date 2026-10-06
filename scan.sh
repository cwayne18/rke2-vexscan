#!/bin/bash

# Scan RKE2's shipped container images with vexscan (github.com/cwayne18/vexscan)
# and emit a JSON report. Two modes:
#
#   * branch (default "master"): reproduce the image list by running the
#     upstream scripts/build-images in a sandbox, then scan that list.
#   * --release <version>: scan the published rke2-images list straight from the
#     GitHub release, handing vexscan the URL directly.
#
# In both modes, ./gen-rke2-vexscan turns the bare image list into a fleet list
# (entrypoint=/roots= assertions saying how RKE2 actually starts each image,
# not just what its own config declares) before handing it to vexscan. If
# python3, PyYAML or helm are missing, or generation fails for any reason, the
# scan falls back to the bare image list with a warning rather than aborting.
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
# Registry used to reproduce PRIME builds. build-images emits the PRIME/hardened
# image variants only when REGISTRY != docker.io; the final scan targets
# registry.rancher.com.
prime_registry="registry.rancher.com"
release_version=""

usage() {
    echo "Usage: $0 [branch] [--release <version>] [--prime] [--no-prime]"
    echo "          [--vexhub <url>] [--prefer-vendor <vendor>] [--severity <list>]"
    echo "          [--fixed-only] [--no-fixed-only] [--runtime] [--no-runtime]"
    echo "          [--output <file>]"
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
    echo "  $0 --output rke2-master.json"
    echo ""
    echo "By default the report is limited to CRITICAL/HIGH findings that have a fix."
    echo "In branch mode the rke2-runtime image is scanned from a rancher/rke2 CI"
    echo "artifact (disable with --no-runtime)."
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
# to a registry, so it cannot be pulled. Instead we scan the real runtime image
# tarball published as a rancher/rke2 CI artifact (see fetch_runtime_layout).
runtime_layout=""
runtime_ref=""
runtime_source_desc=""
runtime_source_url=""
runtime_expected_tag=""
runtime_run_id=""
runtime_artifact_name=""

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
# ref, so a ref from images.txt and a RepoTag read back out of a CI tarball can
# be compared by version alone regardless of registry/namespace differences.
tag_component() {
    local ref="$1"
    echo "${ref##*:}"
}

# fetch_runtime_layout locates the rke2-runtime image tarball from a completed
# rancher/rke2 CI run for the given branch and converts it to an OCI layout that
# vexscan can scan with --haul (vexscan reads a registry or an OCI layout, while
# a CI tarball is a docker-save archive). On success it sets runtime_layout,
# runtime_ref and the runtime_source_* metadata; on any problem it warns and
# leaves runtime_layout empty so the rest of the scan proceeds unaffected.
#
# A CI run on $ref is not a guarantee its artifacts build $ref's own version --
# e.g. an upgrade-path test run on master can also bundle an older release
# line's runtime image. A completed run's artifact is only accepted once its
# embedded RepoTag version is checked against $expected_tag (when known, i.e.
# whenever images.txt produced one); a mismatch is treated the same as "no
# matching artifact" and the search keeps trying older runs.
fetch_runtime_layout() {
    local ref="$1"
    local expected_tag="$2"
    local desc="branch '${ref}'"

    if [[ -n "$expected_tag" ]]; then
        runtime_expected_tag="$expected_tag"
    fi

    if ! command -v gh >/dev/null 2>&1; then
        echo "Warning: gh CLI not found; skipping runtime image scan"
        return 1
    fi
    if ! command -v skopeo >/dev/null 2>&1; then
        echo "Warning: skopeo not found; skipping runtime image scan"
        return 1
    fi

    echo "Locating rke2-runtime image tarball from rancher/rke2 CI for ${desc}..."
    if [[ -n "$expected_tag" ]]; then
        echo "Expecting rke2-runtime version: $(tag_component "$expected_tag")"
    fi
    local run_ids
    run_ids=$(gh run list -R rancher/rke2 -b "$ref" -s completed --limit 50 \
        --json databaseId --jq '.[].databaseId' 2>/dev/null)
    if [[ -z "$run_ids" ]]; then
        echo "Warning: no completed rancher/rke2 workflow runs found for ${desc}; skipping runtime image scan"
        return 1
    fi

    # Walk completed runs newest-first, accepting the first one whose runtime
    # image artifact (uploaded as rke2-test-artifacts / rke2-runtime /
    # rke2-images) actually contains the expected version. A run on $ref is not
    # a guarantee of that -- e.g. an upgrade-path test run on master can also
    # bundle an older release line's runtime image under a matching artifact
    # name -- so a version mismatch is treated like "no artifact" and the
    # search keeps trying older runs rather than silently scanning the wrong
    # image.
    local run_id="" artifact_name="" repo_tag="" candidate names match mismatch_seen=""
    for candidate in $run_ids; do
        names=$(gh api "repos/rancher/rke2/actions/runs/${candidate}/artifacts" --paginate \
            --jq '.artifacts[] | select(.expired == false) | .name' 2>/dev/null)
        match=$(printf '%s\n' "$names" | grep -E 'rke2-runtime|rke2-test-artifacts|rke2-images' | head -1)
        [[ -z "$match" ]] && continue

        local artifact_dir="$work_dir/runtime-artifact"
        rm -rf "$artifact_dir"
        mkdir -p "$artifact_dir"
        if ! gh run download "$candidate" -R rancher/rke2 -n "$match" -D "$artifact_dir" 2>/dev/null; then
            echo "Warning: failed to download artifact '${match}' from run ${candidate}; trying an older run"
            continue
        fi

        # Prefer a runtime-specific tarball, otherwise the linux-amd64 image
        # archive produced by build-image-runtime.
        local archive
        archive=$(find "$artifact_dir" -type f \( -name 'rke2-runtime*.tar.zst' -o -name 'rke2-runtime*.tar' \) | head -1)
        if [[ -z "$archive" ]]; then
            archive=$(find "$artifact_dir" -type f -name 'rke2-images.linux-amd64.tar.zst' | head -1)
        fi
        if [[ -z "$archive" ]]; then
            archive=$(find "$artifact_dir" -type f -name 'rke2-images.linux-amd64.tar' | head -1)
        fi
        if [[ -z "$archive" ]]; then
            echo "Warning: artifact '${match}' from run ${candidate} contained no image tarball; trying an older run"
            continue
        fi

        local tar_path
        if [[ "$archive" == *.zst ]]; then
            tar_path="${archive%.zst}"
            if ! zstd -d -f "$archive" -o "$tar_path" 2>/dev/null; then
                echo "Warning: failed to decompress artifact '${match}' from run ${candidate}; trying an older run"
                continue
            fi
        else
            tar_path="$archive"
        fi

        repo_tag=$(runtime_repo_tag "$tar_path")
        [[ -z "$repo_tag" ]] && repo_tag="rancher/rke2-runtime:ci-${ref}"

        if [[ -n "$expected_tag" && "$(tag_component "$repo_tag")" != "$(tag_component "$expected_tag")" ]]; then
            echo "Warning: run ${candidate}'s artifact '${match}' is rke2-runtime $(tag_component "$repo_tag"), not the expected $(tag_component "$expected_tag") for ${desc}; trying an older run"
            mismatch_seen="true"
            continue
        fi

        run_id="$candidate"
        artifact_name="$match"
        break
    done

    if [[ -z "$run_id" ]]; then
        if [[ -n "$mismatch_seen" ]]; then
            echo "Warning: no rancher/rke2 CI run for ${desc} had a runtime image artifact matching the expected version; skipping runtime image scan"
        else
            echo "Warning: no rancher/rke2 CI run for ${desc} has a runtime image artifact; skipping runtime image scan"
        fi
        return 1
    fi

    echo "Found artifact '${artifact_name}' in rancher/rke2 run ${run_id} (rke2-runtime ${repo_tag})"
    runtime_ref="$repo_tag"

    # $tar_path is still the decompressed/raw tarball from the loop iteration
    # that matched and broke out above (bash `local` is function-scoped, not
    # per-iteration).
    local layout_dir="$work_dir/runtime-oci"
    rm -rf "$layout_dir"
    mkdir -p "$layout_dir"
    echo "Converting runtime tarball to an OCI layout (${repo_tag})..."
    if ! skopeo copy "docker-archive:${tar_path}" "oci:${layout_dir}:${repo_tag}" >/dev/null 2>&1; then
        # Some CI archives are OCI rather than docker-save; try that transport too.
        if ! skopeo copy "oci-archive:${tar_path}" "oci:${layout_dir}:${repo_tag}" >/dev/null 2>&1; then
            echo "Warning: failed to convert runtime tarball to an OCI layout; skipping runtime image scan"
            return 1
        fi
    fi

    runtime_layout="$layout_dir"
    runtime_source_url="https://github.com/rancher/rke2/actions/runs/${run_id}"
    runtime_source_desc="rancher/rke2 CI artifact '${artifact_name}' from ${desc}"
    runtime_run_id="$run_id"
    runtime_artifact_name="$artifact_name"
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

rm -f "$output_file" fleet.txt
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
    # Build-from-source mode: run the upstream build-images script in a temp
    # sandbox and collect the generated image lists into a single images.txt.
    work_dir=$(mktemp -d)
    cleanup() {
        rm -rf "$work_dir"
    }
    trap cleanup EXIT

    mkdir -p "$work_dir/scripts" "$work_dir/bin" "$work_dir/build"

    raw_repo="rancher/rke2"
    raw_ref="$ref_path"

    download_build_scripts() {
        curl -fsSL "https://raw.githubusercontent.com/${raw_repo}/${raw_ref}/scripts/version.sh" \
            -o "$work_dir/scripts/version.sh" 2>/dev/null \
        && curl -fsSL "https://raw.githubusercontent.com/${raw_repo}/${raw_ref}/scripts/build-images" \
            -o "$work_dir/scripts/build-images" 2>/dev/null
    }

    if ! download_build_scripts; then
        echo "Error: failed to fetch build scripts for ${source_desc} (${ref_path})"
        exit 1
    fi

    chmod +x "$work_dir/scripts/build-images"

    if [[ "$use_prime_ingress" == "true" ]]; then
        ingress_nginx_hardened_tag=$(sed -n 's/^INGRESS_NGINX_HARDENED_TAG=//p' "$work_dir/scripts/build-images" | head -n 1)
        ingress_nginx_prime_tag=$(sed -n 's/^INGRESS_NGINX_PRIME_TAG=//p' "$work_dir/scripts/build-images" | head -n 1)

        if [[ -z "$ingress_nginx_hardened_tag" || -z "$ingress_nginx_prime_tag" ]]; then
            echo "Error: failed to determine ingress-nginx hardened/prime tags from build-images"
            exit 1
        fi
    fi

    # build-images shells out to git for version metadata. In a sandbox with no
    # checkout, stub it so the script runs without a real repo.
    cat <<'EOF' > "$work_dir/bin/git"
#!/bin/sh
case "$1" in
    rev-parse)
        echo deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
        ;;
    diff|status|tag)
        exit 0
        ;;
    log)
        echo deadbeefdeadbeefdeadbeefdeadbeefdeadbeef someone@example.com
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod +x "$work_dir/bin/git"

    # Run scripts/build-images with scan-specific controls. Image lists are
    # generated without pulling anything (PULL_CMD stubbed) and without building
    # the runtime image, which we don't scan here.
    run_build_images() {
        local out_dir="$1"
        local registry_override="$2"
        (
            export PATH="$work_dir/bin:$PATH"
            export GOARCH="${GOARCH:-$(go env GOARCH)}"
            export GOOS="${GOOS:-$(go env GOOS)}"
            export BUILD_DIR="$out_dir"
            export SKIP_BUILD_IMAGE_RUNTIME=1
            export PULL_CMD=echo
            export PULL_CMD_CORE=echo
            [[ -n "$registry_override" ]] && export REGISTRY="$registry_override"
            bash "$work_dir/scripts/build-images"
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
    # for this exact ref, and fetch_runtime_layout uses it below to reject a CI
    # artifact that doesn't actually match $branch's own build.
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
        fetch_runtime_layout "$branch" "$expected_runtime_tag"
    else
        echo "Skipping runtime image scan (--no-runtime)"
    fi
fi

echo "Running vexscan (vexhub=${vexhub}, prefer-vendor=${prefer_vendor}, severity=${severity_filter:-all})..."
vexscan_args=(
    --images-from "$images_source"
    --all --triage
    --vexhub "$vexhub"
    --prefer-vendor "$prefer_vendor"
)
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
        --prefer-vendor "$prefer_vendor"
    )
    if [[ -n "$severity_filter" ]]; then
        runtime_args+=(--severity "$severity_filter")
    fi
    runtime_args+=(--format json)

    if vexscan "${runtime_args[@]}" > "$runtime_output" && [[ -s "$runtime_output" ]]; then
        python3 - "$output_file" "$runtime_output" \
            "$runtime_source_url" "$runtime_run_id" "$runtime_artifact_name" \
            "$runtime_expected_tag" "$runtime_ref" <<'PY'
import json
import sys

main_path, runtime_path, ci_run_url, ci_run_id, artifact_name, expected_tag, actual_tag = sys.argv[1:8]
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

# Record which CI run/artifact actually supplied the runtime image and
# whether its version matched what was expected for this branch, so a future
# mismatch (e.g. a CI run bundling an unrelated release line's runtime image
# under the same artifact name) is auditable from the report itself instead
# of only from scan.sh's console output.
main["runtime_image_source"] = {
    "ci_run_url": ci_run_url or None,
    "ci_run_id": ci_run_id or None,
    "artifact_name": artifact_name or None,
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
