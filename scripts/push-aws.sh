#!/bin/bash
#
# push-aws.sh - Build and push the tmi-tf-wh container to Amazon ECR
#
# Prerequisites: AWS CLI (authenticated), Docker with buildx, grype, jq.
#
# Usage:
#   ./scripts/push-aws.sh [--tag TAG] [--region REGION] [--profile PROFILE]
#                         [--repo NAME] [--platform PLATFORM] [--no-cache]
#                         [--fail-on SEVERITY] [--scan-only]
#   ./scripts/push-aws.sh --check-report GRYPE_JSON [--fail-on SEVERITY]
#
# Defaults: tag=latest, region=$AWS_REGION or us-east-1, profile=$AWS_PROFILE or tmi,
#           repo=tmi-tf-wh, platform=linux/amd64 (EKS nodes are x86_64),
#           fail-on=high.
#
# When tag is "latest" the image is also tagged v<version from pyproject.toml>.
#
# After the push, grype scans the pushed image (OS packages, Python packages
# and the Go terraform binary). The script exits 3 and lists the findings if
# any vulnerability at or above --fail-on has a fixed version available; do
# not deploy that tag. Findings with severity Unknown count as failing.
# ECR's own BASIC scan-on-push is not a substitute: it scans once at push and
# misses language packages. --scan-only rescans an existing tag without
# building; --check-report applies the same gate to a saved
# `grype -o json` report (no AWS or Docker needed).
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

REGION="${AWS_REGION:-us-east-1}"
PROFILE="${AWS_PROFILE:-tmi}"
REPO="tmi-tf-wh"
TAG="latest"
PLATFORM="linux/amd64"
NO_CACHE=false
FAIL_ON="high"
SCAN_ONLY=false
CHECK_REPORT=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --tag) TAG="$2"; shift 2 ;;
        --region) REGION="$2"; shift 2 ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --repo) REPO="$2"; shift 2 ;;
        --platform) PLATFORM="$2"; shift 2 ;;
        --no-cache) NO_CACHE=true; shift ;;
        --fail-on) FAIL_ON="$2"; shift 2 ;;
        --scan-only) SCAN_ONLY=true; shift ;;
        --check-report) CHECK_REPORT="$2"; shift 2 ;;
        --help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

case "$FAIL_ON" in
    negligible|low|medium|high|critical) ;;
    *) echo "--fail-on must be one of negligible, low, medium, high, critical (got '${FAIL_ON}')" >&2; exit 1 ;;
esac

# check_report FILE: exit 0 when no fixable finding is at or above FAIL_ON,
# 3 (listing the findings) when one is, 1 when FILE is not a grype JSON report.
check_report() {
    local report="$1" hits
    [[ -f "$report" ]] || { echo "grype report not found: ${report}" >&2; return 1; }
    if ! hits=$(jq -r --arg min "$FAIL_ON" '
        def rank: {"negligible":0,"low":1,"medium":2,"high":3,"critical":4}[ascii_downcase] // 5;
        if (type != "object") or (.matches | type) != "array" then error("not a grype JSON report") else . end
        | [.matches[]
           | select(.vulnerability.fix.state == "fixed")
           | select((.vulnerability.severity // "Unknown" | rank) >= ($min | rank))
           | [(.vulnerability.severity // "Unknown"), .vulnerability.id, .artifact.name,
              .artifact.version, (.vulnerability.fix.versions | join(","))]
           | @tsv]
        | unique[]' "$report"); then
        echo "could not read grype report ${report}" >&2
        return 1
    fi
    if [[ -n "$hits" ]]; then
        echo "Fixable vulnerabilities at or above ${FAIL_ON} ($(wc -l <<<"$hits" | tr -d ' ')):" >&2
        printf 'SEVERITY\tID\tPACKAGE\tVERSION\tFIXED IN\n%s\n' "$hits" >&2
        return 3
    fi
    echo "No fixable vulnerabilities at or above ${FAIL_ON}." >&2
}

if [[ -n "$CHECK_REPORT" ]]; then
    command -v jq >/dev/null || { echo "jq not found in PATH" >&2; exit 1; }
    rc=0; check_report "$CHECK_REPORT" || rc=$?
    exit "$rc"
fi

for tool in aws docker grype jq; do
    command -v "$tool" >/dev/null || { echo "$tool not found in PATH" >&2; exit 1; }
done

ACCOUNT=$(aws sts get-caller-identity --profile "$PROFILE" --query Account --output text)
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
IMAGE="${REGISTRY}/${REPO}"
VERSION=$(grep '^version' "${PROJECT_ROOT}/pyproject.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')

echo "Logging in to ${REGISTRY}" >&2
aws ecr get-login-password --profile "$PROFILE" --region "$REGION" \
    | docker login --username AWS --password-stdin "$REGISTRY"

# Resolve the tmi-clients branch to a commit so a new client release busts the cached clone layer.
TMI_CLIENT_SHA=$(git ls-remote https://github.com/ericfitz/tmi-clients.git refs/heads/main | cut -f1)
[[ -n "$TMI_CLIENT_SHA" ]] || { echo "could not resolve tmi-clients main" >&2; exit 1; }

BUILD_ARGS=(
    --platform "$PLATFORM"
    --file "${PROJECT_ROOT}/deploy/docker/Dockerfile.aws"
    --tag "${IMAGE}:${TAG}"
    --build-arg "BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    --build-arg "GIT_COMMIT=$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    --build-arg "TMI_CLIENT_SHA=${TMI_CLIENT_SHA}"
    --push
)
[[ "$TAG" == "latest" && -n "$VERSION" ]] && BUILD_ARGS+=(--tag "${IMAGE}:v${VERSION}")
[[ "$NO_CACHE" == true ]] && BUILD_ARGS+=(--no-cache)

if [[ "$SCAN_ONLY" != true ]]; then
    echo "Building ${IMAGE}:${TAG} for ${PLATFORM}" >&2
    docker buildx build "${BUILD_ARGS[@]}" "$PROJECT_ROOT"
    echo "Pushed ${IMAGE}:${TAG}" >&2
fi

REPORT="$(mktemp "${TMPDIR:-/tmp}/grype-report.XXXXXX")"
trap 'rm -f "$REPORT"' EXIT
echo "Scanning ${IMAGE}:${TAG} (${PLATFORM}) with grype" >&2
grype -q --platform "$PLATFORM" -o json "registry:${IMAGE}:${TAG}" >"$REPORT"
rc=0; check_report "$REPORT" || rc=$?
if [[ "$rc" -eq 3 ]]; then
    echo "Do not deploy ${IMAGE}:${TAG}; fix the findings above and rebuild (--no-cache picks up OS updates)." >&2
fi
exit "$rc"
