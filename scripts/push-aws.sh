#!/bin/bash
#
# push-aws.sh - Build and push the tmi-tf-wh container to Amazon ECR
#
# Prerequisites: AWS CLI (authenticated), Docker with buildx.
#
# Usage:
#   ./scripts/push-aws.sh [--tag TAG] [--region REGION] [--profile PROFILE]
#                         [--repo NAME] [--platform PLATFORM] [--no-cache]
#
# Defaults: tag=latest, region=$AWS_REGION or us-east-1, profile=$AWS_PROFILE or tmi,
#           repo=tmi-tf-wh, platform=linux/amd64 (EKS nodes are x86_64).
#
# When tag is "latest" the image is also tagged v<version from pyproject.toml>.
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

while [[ $# -gt 0 ]]; do
    case $1 in
        --tag) TAG="$2"; shift 2 ;;
        --region) REGION="$2"; shift 2 ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --repo) REPO="$2"; shift 2 ;;
        --platform) PLATFORM="$2"; shift 2 ;;
        --no-cache) NO_CACHE=true; shift ;;
        --help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

for tool in aws docker; do
    command -v "$tool" >/dev/null || { echo "$tool not found in PATH" >&2; exit 1; }
done

ACCOUNT=$(aws sts get-caller-identity --profile "$PROFILE" --query Account --output text)
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
IMAGE="${REGISTRY}/${REPO}"
VERSION=$(grep '^version' "${PROJECT_ROOT}/pyproject.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')

echo "Logging in to ${REGISTRY}" >&2
aws ecr get-login-password --profile "$PROFILE" --region "$REGION" \
    | docker login --username AWS --password-stdin "$REGISTRY"

BUILD_ARGS=(
    --platform "$PLATFORM"
    --file "${PROJECT_ROOT}/deploy/docker/Dockerfile.aws"
    --tag "${IMAGE}:${TAG}"
    --build-arg "BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    --build-arg "GIT_COMMIT=$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    --push
)
[[ "$TAG" == "latest" && -n "$VERSION" ]] && BUILD_ARGS+=(--tag "${IMAGE}:v${VERSION}")
[[ "$NO_CACHE" == true ]] && BUILD_ARGS+=(--no-cache)

echo "Building ${IMAGE}:${TAG} for ${PLATFORM}" >&2
docker buildx build "${BUILD_ARGS[@]}" "$PROJECT_ROOT"
echo "Pushed ${IMAGE}:${TAG}" >&2
