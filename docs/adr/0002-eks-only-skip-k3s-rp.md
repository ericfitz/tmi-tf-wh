# ADR 0002: EKS is the only deploy target; k3s-rp is skipped

- Status: Accepted
- Date: 2026-10-03
- Decision maker: Eric Fitzgerald (human decision)

## Context

The other TMI services also run on k3s-rp, but tmi-tf-wh never has. Its job
queue provider (`QUEUE_PROVIDER`, `tmi_tf/config.py`) is one of `oci`, `aws`
or `none`, and `none` runs no worker pool, so there is no queue that works on
k3s-rp without new code.

## Decision

Eric chose to skip k3s-rp: tmi-tf-wh deploys only to AWS EKS (`tmi-eks`,
namespace `tmi-tf`) plus local development.

## Options if this is revisited

- A Redis queue provider using the tmi-platform Redis.
- SQS reached from k3s-rp (needs AWS credentials on the cluster).
- An in-memory queue (jobs are lost on pod restart).

## Consequences

- No k3s-rp manifests or queue provider are maintained.
- Adding k3s-rp later needs one of the options above first.
