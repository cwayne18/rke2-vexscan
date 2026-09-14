#!/bin/bash

# Scan RKE2's shipped container images with vexscan (github.com/cwayne18/vexscan)
# and emit a JSON report. Two modes:
#
#   * branch (default "master"): reproduce the image list by running the
#     upstream scripts/build-images in a sandbox, then scan that list.
#   * --release <version>: scan the published rke2-images list straight from the
#     GitHub release, handing vexscan the URL directly.
#
# vexscan does its own triage and VEX resolution, so the output JSON is fed to
# contrib/vexscan-dashboard.py to render the HTML pages.

set -o pipefail

output_file="scan.json"
branch=""
use_prime_ingress="false"
prime_explicit=""
vexhub="https://github.com/rancher/vexhub"
prefer_vendor="suse"
# Registry used to reproduce PRIME builds. build-images emits the PRIME/hardened
# image variants only when REGISTRY != docker.io; the final scan targets
# registry.rancher.com.
prime_registry="registry.rancher.com"
release_version=""

usage() {
    echo "Usage: $0 [branch] [--release <version>] [--prime] [--no-prime]"
    echo "          [--vexhub <url>] [--prefer-vendor <vendor>] [--output <file>]"
    echo ""
    echo "Examples:"
    echo "  $0                         # scan master (built from source)"
    echo "  $0 release-1.35            # scan a release branch built from source"
    echo "  $0 --release v1.37.0+rke2r1"
    echo "  $0 --release v1.37.0-rke2r1"
    echo "  $0 --prime                 # rewrite images to the prime registry"
    echo "  $0 --output rke2-master.json"
    echo ""
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

rm -f "$output_file"
rm -f images.txt

# vexscan's --images-from accepts a URL or a file. In release mode we hand it
# the release URL untouched; in branch mode we build a local images.txt.
images_source=""

echo "Scanning using ${source_desc}"

if [[ -n "$release_version" ]]; then
    # Release mode: point vexscan straight at the published images list.
    images_source="https://github.com/rancher/rke2/releases/download/${release_tag_url}/rke2-images.linux-amd64.txt"
    echo "Using release images list: $images_source"
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
    fi

    echo "Built image list with $(wc -l < images.txt | tr -d ' ') images"
    images_source="./images.txt"
fi

echo "Running vexscan (vexhub=${vexhub}, prefer-vendor=${prefer_vendor})..."
vexscan \
    --images-from "$images_source" \
    --all --triage \
    --vexhub "$vexhub" \
    --prefer-vendor "$prefer_vendor" \
    --format json > "$output_file"

if [[ ! -s "$output_file" ]]; then
    echo "Error: vexscan produced no output"
    exit 1
fi

echo "Wrote scan report to ${output_file}"
