# AWS (EKS) Deployment Design

**Date:** 2026-09-04
**Status:** Approved for planning
**Supersedes for AWS:** nothing. The OCI/OKE design (`2026-03-19-oci-deployment-design.md`) remains the OCI target.

## Goal

Run `tmi-tf-wh` on AWS, in the account behind the `tmi` CLI profile, wired to the
TMI deployment already running there. Reuse what that deployment provides
(cluster, load balancer controller, DNS zone, state bucket) rather than
building a parallel platform.

## What already exists (discovered 2026-09-03)

| Item | Value |
|------|-------|
| Account / profile | `967218005408` / `tmi` (profile default region us-east-2, but all compute is in **us-east-1**) |
| EKS cluster | `tmi-eks`, v1.36, 2 x `t3.medium` (x86_64), private subnets with NAT |
| TMI namespace | `tmi-platform` (`tmi-server`, `redis`, ...) |
| Ingress | AWS Load Balancer Controller v2.17.1; `api.tmi.dev` is an internet-facing ALB Ingress with ACM cert + Route53 CNAME |
| IAM | IRSA OIDC provider exists; TMI's `tmi-api` ServiceAccount uses it |
| DNS | Route53 hosted zone `tmi.dev` in the same account |
| State | S3 `tmi-tfstate-967218005408` + DynamoDB lock table `tmi-tf-locks` |
| Headroom | ~1.2 vCPU / ~2 GiB unrequested across the two nodes |

Two facts constrain the design:

1. **TMI validates webhook URLs as HTTPS-only and blocks private IPs on
   delivery.** An in-cluster `http://` Service URL is rejected, so the listener
   needs a public HTTPS hostname even though it runs next to TMI.
2. **Nodes are x86_64.** The image must be built for `linux/amd64`.

## Human-made architectural decisions

Recorded per the design-changes rule. Made by Eric Fitzgerald on 2026-09-04.

| Decision | Choice | Alternative considered |
|----------|--------|------------------------|
| Compute | Existing `tmi-eks` cluster, new namespace `tmi-tf`, 1 replica | New cluster / ECS / Lambda |
| Queue | **SQS** + dead-letter queue, new `AwsQueueProvider` | In-process `memory` provider (loses jobs on restart) |
| Secrets | Kubernetes `Secret`, `SECRET_PROVIDER=none` (same as `tmi-server` on this cluster) | Secrets Manager + `AwsSecretProvider` (upgrade path if rotation is needed) |
| Public hostname | **`webhook.tmi.dev`**, shared by all future TMI webhook apps | One hostname per app |
| Multiplexing | ALB IngressGroup; each app owns an Ingress + path prefix (see below) | A demux service in front of the apps |
| LLM | ~~`anthropic` / `claude-fable-5-1`~~ **Amended by Eric 2026-09-06: `LLM_PROVIDER=openai`, `LLM_MODEL=gpt-daybreak-blue-latest`**, key from `~/.keys/OPENAI_CYBER_API_KEY` | OCI GenAI (OKE default); `gpt-5.6-cyber` (not enabled on the key) |
| Terraform layout | Move OCI to `infra/oci/`, add `infra/aws/` | Keep OCI at `infra/` root |
| TMI write auth (Eric, 2026-09-06) | tmi-tf-wh authenticates to the TMI API with **client_credentials of a dedicated non-admin automation user** (member of `tmi-automation`, writer on the threat model); the webhook is only a trigger. TMI will add an opt-in `direct_write` flag on the credential so the invoker-only gate (T18) lets it through to normal ACL checks; ADR + issues tracked in the `tmi` repo. | Port to the addon flow and write back with the per-delivery delegation JWT — rejected: protocol transition from webhook auth to OAuth, and the JWT TTL is 60 s vs 10–40 min jobs |

## Architecture

```
TMI (tmi-platform ns)  --HTTPS-->  webhook.tmi.dev (ALB, IngressGroup "tmi-webhooks")
                                        |  /tf/*
                                        v
                               tmi-tf-wh pod (tmi-tf ns)
                                 |  publish        ^ consume
                                 v                 |
                              SQS tmi-tf-wh-jobs  (+ DLQ)
                                 |
                       worker -> GitHub clone -> Anthropic -> TMI API (api.tmi.dev)
```

One pod runs both the FastAPI webhook receiver and the worker pool (as today).
The pod's ServiceAccount is bound via IRSA to a role that may only
send/receive/delete on its own queue.

### Multiplexing `webhook.tmi.dev`

The ALB *is* the demux; no extra service is needed.

- All webhook apps set `alb.ingress.kubernetes.io/group.name: tmi-webhooks` on
  their Ingress. The Load Balancer Controller merges every Ingress in the group
  (across namespaces) into **one ALB** with one listener and one rule per path.
- Each app owns a path prefix. `tmi-tf-wh` claims `/tf`; its endpoints become
  `https://webhook.tmi.dev/tf/webhook`, `/tf/health`, `/tf/status`.
- A future app adds its own Ingress (in its own namespace, its own repo) with
  the same `group.name` and its own prefix. Nothing in this repo changes.
- The ALB does not rewrite paths, so the app must serve under its prefix. A
  new `URL_PREFIX` env var (default `""`) mounts the FastAPI routes on an
  `APIRouter(prefix=URL_PREFIX)`. Local and OCI deployments leave it unset.
- The ALB health check for this app's target group is `/tf/health`
  (`alb.ingress.kubernetes.io/healthcheck-path`).
- If routing ever needs more than a path (e.g. a header), the controller's
  `conditions.<service>` annotation handles it on the same ALB. Still no demux.

**Shared assets.** The ACM certificate for `webhook.tmi.dev` and its Route53
CNAME are created once. The first tenant (this repo) creates them. When a
second app arrives they should move to a shared stack (TMI's Terraform or a
small `tmi-webhooks` stack) via `terraform state mv`/`import`; documented as a
known follow-up, not built now.

## Components

### Terraform: `infra/aws/`

Backend: S3 `tmi-tfstate-967218005408`, key `tmi-tf-wh/aws/terraform.tfstate`,
DynamoDB `tmi-tf-locks`, bucket/table supplied via `-backend-config` like TMI.

Providers: `aws` (profile `tmi`, region `us-east-1`), `kubernetes` (exec auth
via `aws eks get-token`, same as TMI's module).

Inputs (tfvars): cluster name, hosted zone name, hostname, URL prefix, image
tag, LLM provider/model, `tmi_server_url`, `max_concurrent_jobs`, plus the
five secret values as `sensitive` variables in an untracked
`secrets.auto.tfvars`.

Resources:

| File | Resources |
|------|-----------|
| `ecr.tf` | ECR repo `tmi-tf-wh`, scan-on-push, keep last 10 images |
| `sqs.tf` | `tmi-tf-wh-jobs` (queue default visibility 900 s; the worker overrides per receive with `JOB_TIMEOUT`, retention 24 h, redrive after 3) + `tmi-tf-wh-jobs-dlq` |
| `iam.tf` | IRSA role trusting `system:serviceaccount:tmi-tf:tmi-tf-wh`; inline policy `sqs:SendMessage/ReceiveMessage/DeleteMessage/GetQueueAttributes` on the jobs queue ARN only |
| `dns.tf` | ACM cert for the hostname (DNS-validated in the zone) + Route53 CNAME to the ALB hostname from the Ingress status |
| `k8s.tf` | Namespace, ServiceAccount (IRSA annotation), Secret, Deployment, ClusterIP Service, Ingress |
| `outputs.tf` | webhook URL, queue URL, ECR repo URL, IRSA role ARN |

Deployment env (non-secret): `QUEUE_PROVIDER=aws`, `QUEUE_URL`, `AWS_REGION`,
`SECRET_PROVIDER=none`, `URL_PREFIX=/tf`, `LLM_PROVIDER`, `LLM_MODEL`,
`TMI_SERVER_URL`, `TMI_OAUTH_IDP=tmi`, `TMI_CLIENT_PATH=/opt/tmi-client`,
`SERVER_PORT=8080`, `MAX_CONCURRENT_JOBS`. Secrets come from the Secret via
`envFrom`. Probes hit `${URL_PREFIX}/health`. Requests 500m/512Mi, limits
1/1Gi (same as OKE).

Ingress annotations mirror `tmi-server`'s: `scheme: internet-facing`,
`target-type: ip`, `listen-ports: [{HTTPS:443}]`, `certificate-arn`,
plus `group.name: tmi-webhooks` and `healthcheck-path: /tf/health`. No HTTP
listener: TMI only ever calls HTTPS.

### Application code

- `tmi_tf/providers/aws.py`: `AwsQueueProvider(queue_url, region)` using
  `boto3` SQS `send_message` / `receive_message(VisibilityTimeout, MaxNumberOfMessages)`
  / `delete_message`. Same JSON body contract and same "delete unparseable
  message" behavior as the OCI provider. Lazy client init.
- `tmi_tf/providers/__init__.py`: `get_queue_provider` gains the `"aws"`
  branch; error text lists `oci`, `aws`, `memory`.
- `tmi_tf/config.py`: `queue_url` (from `QUEUE_URL`); infer
  `queue_provider="aws"` when `QUEUE_URL` is set and no explicit provider;
  `url_prefix` (from `URL_PREFIX`, default `""`).
- `tmi_tf/server.py`: routes move onto `APIRouter(prefix=config.url_prefix)`;
  behavior unchanged when the prefix is empty.
- `pyproject.toml`: add `boto3`.
- `.env.example`: document `QUEUE_PROVIDER=aws`, `QUEUE_URL`, `URL_PREFIX`.

### Build/push

- `deploy/docker/Dockerfile.aws`: fix the header comment (amd64).
- `scripts/push-aws.sh`: ECR login with profile `tmi`, `docker buildx build
  --platform linux/amd64 -f deploy/docker/Dockerfile.aws --push`, tags
  `latest` and `v<pyproject version>`, same BUILD_DATE/GIT_COMMIT args as
  `push-oci.sh`. Far simpler than the OCI script because ECR needs no
  discovery.

### Docs

- `infra/aws/README.md`: prerequisites, `backend.hcl` example, apply order
  (push image first, then `terraform apply`), the manual TMI-side steps
  (create a client_credentials OAuth client; create a webhook subscription to
  `https://webhook.tmi.dev/tf/webhook` with the shared secret), and the
  multiplexing contract for future apps.
- `deploy/docker/README.md`: mention `push-aws.sh`.

## Data flow

1. TMI POSTs to `https://webhook.tmi.dev/tf/webhook` with HMAC signature.
2. ALB rule `/tf/*` forwards to the pod IP on 8080.
3. `server.py` verifies subscription id + HMAC, answers challenges, publishes
   the job JSON to SQS, returns 202.
4. Worker pool long-polls SQS (visibility = `JOB_TIMEOUT`, so a job is never redelivered mid-run), runs the analysis, writes
   notes/diagram/threats to TMI via `api.tmi.dev` (public ALB; the pod egresses
   through the NAT gateway), deletes the message.
5. Three failed receives send the message to the DLQ.

## Error handling

- Missing/placeholder secret values: `ApiKeyLLMProvider` already raises at
  startup; the pod crash-loops visibly instead of silently doing nothing.
- SQS unreachable: existing worker retry/backoff (`retry.py`) applies; the
  webhook returns 500 on publish failure as it does for OCI.
- Bad message bodies: deleted and logged, as with OCI.
- Certificate validation waits on DNS; `aws_acm_certificate_validation`
  blocks apply until the cert is issued.

## Testing

- Unit: `tests/test_providers_aws.py` with a stubbed boto3 client covering
  publish, consume (visibility timeout passthrough), delete, and unparseable
  body deletion; `test_config` cases for `QUEUE_URL` inference and
  `URL_PREFIX`; server tests asserting routes respond under a prefix.
- Terraform: `terraform fmt -check` and `terraform validate` in `infra/aws`
  and `infra/oci`.
- Integration (manual, after apply): `curl https://webhook.tmi.dev/tf/health`;
  TMI subscription challenge succeeds; a real threat-model webhook produces
  a note in TMI.

## Out of scope

- Secrets Manager, Bedrock, autoscaling, WAF, a shared `tmi-webhooks` stack.
  Each is a known upgrade with a clear trigger, none is needed for the first
  deployment.

## Estimated cost

One ALB (~$18/month) plus negligible ECR and SQS usage. No new nodes.
