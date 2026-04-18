# Dockerfiles

Per-target Dockerfiles for `tmi-tf-wh`. All expect the repo root as the build context.

| File | Base image | Target | Port |
|------|------------|--------|------|
| `Dockerfile.local` | `cgr.dev/chainguard/wolfi-base` | Docker Desktop / local dev | 8088 |
| `Dockerfile.oci` | `container-registry.oracle.com/os/oraclelinux:9` | Oracle Container Engine (OKE) | 8080 |
| `Dockerfile.aws` | `public.ecr.aws/amazonlinux/amazonlinux:2023` | ECS / EKS / App Runner | 8080 |
| `Dockerfile.azure` | `mcr.microsoft.com/azurelinux/base/core:3.0` | ACI / AKS / Container Apps | 8080 |
| `Dockerfile.gcp` | `gcr.io/google.com/cloudsdktool/cloud-sdk:slim` | Cloud Run / GKE | 8080 |
| `Dockerfile.heroku` | `heroku/heroku:24` | Heroku Container Registry | `$PORT` |

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

The OCI push workflow is wrapped by [scripts/push-oci.sh](../../scripts/push-oci.sh).

## Build args

All non-local Dockerfiles accept:

- `TMI_CLIENT_REPO` — git URL for the TMI Python client (default: `https://github.com/ericfitz/tmi-clients.git`)
- `TMI_CLIENT_REF` — branch/tag (default: `main`)
- `BUILD_DATE`, `GIT_COMMIT` — baked into OCI labels
