# ADR 0001: Python 3.13; deploy targets reduced to AWS and local

- Status: Accepted
- Date: 2026-09-28
- Decision maker: Eric Fitzgerald (human decisions)

## Context

`requires-python` was `>=3.10`, and CI tested 3.10 and 3.13. LiteLLM was capped
below 1.98 because 1.98.0 imported `typing.NotRequired` (3.11+) unguarded and
broke the 3.10 CI leg. LiteLLM 1.103.0 guards the import (verified: it imports
on 3.10.19). Python 3.10 reaches end of life in October 2026.

The repo carried six Dockerfiles (aws, local, oci, azure, gcp, heroku), OCI
Terraform (`infra/oci`, OKE) and `scripts/push-oci.sh`. Only AWS (EKS) is
deployed. Distro Python probed 2026-09-28: Amazon Linux 2023, Wolfi and
Debian 13 (gcp) ship 3.13; Ubuntu 24.04 (heroku), Azure Linux 3 and Oracle
Linux 9 ship only 3.12.

## Decisions

1. Eric chose to lift the LiteLLM cap (now `>=1.103.0`) and move to Python
   3.13 (3.12 only where 3.13 isn't available).
2. Eric chose to build only the AWS and local images: the gcp, azure, heroku
   and oci Dockerfiles, `infra/oci` and `scripts/push-oci.sh` are removed. The
   OCI LLM provider (`tmi_tf/providers/oci.py`) stays; the OCI deployment
   specs/plans under `docs/superpowers` stay as history.

With only AWS (Amazon Linux 2023) and local (Wolfi) left, both ship 3.13, so:
`requires-python = ">=3.13"`, CI tests 3.13, both images run 3.13.

## Consequences

- Code may use 3.13 features; ruff's pyupgrade rules target 3.13.
- Re-adding a deploy target needs a base image with Python 3.13, or a
  uv-managed interpreter in that image.
