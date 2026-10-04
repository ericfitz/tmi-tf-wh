# Dockerfiles

Per-target Dockerfiles for `tmi-tf-wh`. All expect the repo root as the build context.

| File | Base image | Target | Port |
|------|------------|--------|------|
| `Dockerfile.local` | `cgr.dev/chainguard/wolfi-base` | Docker Desktop / local dev | 8088 |
| `Dockerfile.aws` | `public.ecr.aws/amazonlinux/amazonlinux:2023` | EKS (see infra/aws/) | 8080 |

## Building

```bash
# Local (via docker-compose)
docker compose build
docker compose up

# Any target directly
docker buildx build \
  --platform linux/arm64 \
  -f deploy/docker/Dockerfile.<target> \
  -t tmi-tf-wh:<target> .
```

Push workflow: [scripts/push-aws.sh](../../scripts/push-aws.sh) (ECR, amd64 — the EKS nodes are x86_64).

## Build args

`Dockerfile.aws` accepts:

- `TMI_CLIENT_REPO` — git URL for the TMI Python client (default: `https://github.com/ericfitz/tmi-clients.git`)
- `TMI_CLIENT_REF` — branch/tag (default: `main`)
- `TMI_CLIENT_SHA` — commit of `TMI_CLIENT_REF`; changing it invalidates the cached clone (`push-aws.sh` resolves it with `git ls-remote`). Without it, a cached build keeps an old client checkout.

The build copies the newest `python-client-generated/vX.Y.Z` at or above the version in `tmi-api-min-version` (`scripts/select_tmi_client.py`).
- `BUILD_DATE`, `GIT_COMMIT` — baked into OCI labels
