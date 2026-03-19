# tmi-tf-wh OCI Deployment Design

## Overview

Deploy the tmi-tf-wh (TMI Terraform Webhook Analyzer) as a containerized workload on an existing OKE (Oracle Kubernetes Engine) cluster managed by the TMI project's Terraform. The deployment follows the same optional-addon pattern used by TMI-UX: gated by a `tmi_tf_wh_enabled` boolean variable, deploying into the existing `tmi` namespace with a ClusterIP service for internal-only access.

## Context

tmi-tf-wh is a FastAPI webhook server that receives webhook calls from the TMI API, queues analysis jobs via OCI Queue, and processes them asynchronously using a worker pool. Each job clones a GitHub repository, runs a 3-phase LLM analysis pipeline against its Terraform code, and creates notes, data flow diagrams, and STRIDE-classified threats in TMI.

The TMI platform is deployed on OCI using Terraform, with an OKE cluster, OCI Vault for secrets, and OCIR for container images. tmi-tf-wh will be added as an optional component within this existing infrastructure.

## Decisions

- **Deployment target:** Existing OKE cluster managed by TMI Terraform (not a standalone VM or separate cluster).
- **Namespace:** Shared `tmi` namespace (not a separate namespace).
- **Exposure:** ClusterIP service only — no public LoadBalancer. TMI API calls the webhook internally at `http://tmi-tf-wh:8080/webhook`. TMI will be updated to allow HTTP webhook URLs for intra-cluster communication.
- **LLM provider:** OCI Generative AI services only (no external LLM API calls needed from the cluster).
- **Container images:** Must use OCIR only — no DockerHub or other non-Oracle registries.
- **Base images:** `container-registry.oracle.com/os/oraclelinux:9` (build) and `oraclelinux:9-slim` (runtime), matching TMI server and Redis Dockerfiles.
- **Architecture:** arm64 (aarch64) — the OKE node pool uses `VM.Standard.A1.Flex`.
- **TMI Python client:** Cloned from its source repo at container image build time (not vendored or published as a package).
- **Deployment pattern:** Optional addon gated by `tmi_tf_wh_enabled` variable (same as `tmi_ux_enabled`).
- **Both OCI environments:** Changes apply to both `oci-public` and `oci-private` environments.

## Affected Repositories

### 1. tmi-tf-wh (this repo)

#### New files

**`Dockerfile`** — Multi-stage build:

- **Build stage** (`oraclelinux:9`):
  - Install Python 3, pip, git via `dnf`
  - Clone the TMI Python client from its source repo
  - Copy tmi-tf-wh source code
  - Run `pip install .` to install the app and all dependencies
- **Runtime stage** (`oraclelinux:9-slim`):
  - Install Python 3 runtime and git via `microdnf` (git needed at runtime for sparse-cloning repos during analysis)
  - Copy installed Python packages from build stage
  - Create non-root `tmi-tf` user
  - Entrypoint: `uvicorn tmi_tf.server:app --host 0.0.0.0 --port 8080`
  - Expose port 8080

**`.dockerignore`** — Exclude `.venv`, `.git`, `tests/`, `deploy/`, `docs/`, `__pycache__`, `.env`, etc.

#### Deleted files

All files under `deploy/` are removed:

- `deploy/terraform/main.tf`
- `deploy/terraform/compute.tf`
- `deploy/terraform/network.tf`
- `deploy/terraform/loadbalancer.tf`
- `deploy/terraform/queue.tf`
- `deploy/terraform/vault.tf`
- `deploy/terraform/iam.tf`
- `deploy/terraform/logging.tf`
- `deploy/terraform/variables.tf`
- `deploy/terraform/outputs.tf`
- `deploy/terraform/.terraform.lock.hcl`
- `deploy/tmi-tf-wh.service`

These represented a standalone VM deployment that is being replaced by the OKE-based deployment in the TMI repo.

#### No application code changes

The existing application code (`server.py`, `worker.py`, `queue_client.py`, `vault_client.py`, `config.py`) already supports:

- OCI Queue for job dispatch
- OCI Vault for secret loading (with instance principal / workload identity)
- Configurable via environment variables
- Health check endpoint at `/health`

No modifications are needed for OKE deployment. The `TMI_CLIENT_PATH` env var (already in `config.py`) will point to the TMI client location inside the container.

### 2. TMI repo (ericfitz/tmi)

#### `modules/kubernetes/oci/variables.tf` — new variables

```hcl
variable "tmi_tf_wh_enabled" {
  description = "Enable tmi-tf-wh webhook analyzer deployment"
  type        = bool
  default     = false
}

variable "tmi_tf_wh_image_url" {
  description = "Container image URL for tmi-tf-wh"
  type        = string
  default     = null
}

variable "tmi_tf_wh_queue_ocid" {
  description = "OCID of the OCI Queue for tmi-tf-wh job dispatch"
  type        = string
  default     = ""
}

# Resource sizing (with defaults appropriate for LLM-bound workloads)
variable "tmi_tf_wh_cpu_request" { default = "500m" }
variable "tmi_tf_wh_memory_request" { default = "1Gi" }
variable "tmi_tf_wh_cpu_limit" { default = "2" }
variable "tmi_tf_wh_memory_limit" { default = "4Gi" }
```

#### `modules/kubernetes/oci/k8s_resources.tf` — new resources

All gated by `count = var.tmi_tf_wh_enabled ? 1 : 0`:

**ServiceAccount** (`tmi-tf-wh`):
- Dedicated service account for tmi-tf-wh workloads
- `automount_service_account_token = true` (for workload identity)

**ConfigMap** (`tmi-tf-wh-config`):
- `LLM_PROVIDER=oci`
- `OCI_COMPARTMENT_ID` (from existing variable)
- `QUEUE_OCID` (from `var.tmi_tf_wh_queue_ocid`)
- `VAULT_OCID` (from existing `var.vault_ocid`)
- `TMI_SERVER_URL` (internal cluster URL to TMI API)
- `TMI_OAUTH_IDP=tmi`
- `TMI_CLIENT_PATH` (path inside container)
- `MAX_CONCURRENT_JOBS`, `JOB_TIMEOUT`, `SERVER_PORT=8080`
- Plus `var.tmi_tf_wh_extra_env_vars` for deployer overrides

**Deployment** (`tmi-tf-wh`):
- Single replica
- Uses `tmi-tf-wh` service account
- Container image from `var.tmi_tf_wh_image_url`
- Port 8080
- Env from ConfigMap `tmi-tf-wh-config`
- Liveness probe: `GET /health` port 8080 (initial delay 60s, period 30s)
- Readiness probe: `GET /health` port 8080 (initial delay 10s, period 10s)
- Resource requests/limits from variables
- `tmp` emptyDir volume mounted at `/tmp`
- `termination_grace_period_seconds = 60`

**ClusterIP Service** (`tmi-tf-wh`):
- Selector: `app = tmi-tf-wh`
- Port 8080 → target port 8080
- Type: ClusterIP

#### `environments/oci-public/main.tf` — new resources

All gated by `tmi_tf_wh_enabled`:

**OCIR Container Repository:**
```hcl
resource "oci_artifacts_container_repository" "tmi_tf_wh" {
  count          = var.tmi_tf_wh_enabled ? 1 : 0
  compartment_id = var.compartment_id
  display_name   = "${var.name_prefix}/tmi-tf-wh"
  is_public      = true
}
```

**OCI Queue:**
```hcl
resource "oci_queue_queue" "tmi_tf_wh" {
  count                            = var.tmi_tf_wh_enabled ? 1 : 0
  compartment_id                   = var.compartment_id
  display_name                     = "${var.name_prefix}-tf-wh-queue"
  visibility_in_seconds            = 900
  retention_in_seconds             = 86400
  dead_letter_queue_delivery_count = 3
}
```

**IAM Policy** — add queue permissions to existing `vault_access` policy (conditional):
```hcl
statements = concat(
  [
    "Allow dynamic-group ... to read secret-family ...",
    "Allow dynamic-group ... to use keys ...",
  ],
  var.tmi_tf_wh_enabled ? [
    "Allow dynamic-group ... to use queues in compartment id ... where target.queue.id = '${oci_queue_queue.tmi_tf_wh[0].id}'",
    "Allow dynamic-group ... to manage queue-messages in compartment id ... where target.queue.id = '${oci_queue_queue.tmi_tf_wh[0].id}'",
  ] : []
)
```

**Pass-through to kubernetes module:**
```hcl
tmi_tf_wh_enabled    = var.tmi_tf_wh_enabled
tmi_tf_wh_image_url  = var.tmi_tf_wh_image_url
tmi_tf_wh_queue_ocid = var.tmi_tf_wh_enabled ? oci_queue_queue.tmi_tf_wh[0].id : ""
```

#### `environments/oci-public/variables.tf` — new variables

```hcl
variable "tmi_tf_wh_enabled" {
  description = "Enable tmi-tf-wh webhook analyzer deployment"
  type        = bool
  default     = false
}

variable "tmi_tf_wh_image_url" {
  description = "Container image URL for tmi-tf-wh"
  type        = string
  default     = null
}
```

#### `environments/oci-public/terraform.tfvars.example` — new section

```hcl
# ---------------------------------------------------------------------------
# Optional: TMI-TF-WH Webhook Analyzer
# ---------------------------------------------------------------------------
# tmi_tf_wh_enabled   = true
# tmi_tf_wh_image_url = "<region>.ocir.io/<namespace>/tmi/tmi-tf-wh:latest"
```

#### `environments/oci-private/` — identical changes

Same additions to `main.tf`, `variables.tf`, and `terraform.tfvars.example` as oci-public.

## Build Process

Manual for initial deployment:

```bash
# Build arm64 image (from tmi-tf-wh repo root)
docker buildx build --platform linux/arm64 -t <region>.ocir.io/<namespace>/tmi/tmi-tf-wh:latest .

# Push to OCIR
docker push <region>.ocir.io/<namespace>/tmi/tmi-tf-wh:latest

# Deploy via Terraform (from TMI repo, oci-public or oci-private environment)
terraform apply -var="tmi_tf_wh_enabled=true" -var="tmi_tf_wh_image_url=<region>.ocir.io/<namespace>/tmi/tmi-tf-wh:latest"
```

CI/CD automation can be added later.

## Runtime Architecture

```
TMI API Pod                         tmi-tf-wh Pod
+-----------+     HTTP POST         +------------------+
| TMI API   | -------------------> | FastAPI Server    |
| server    |  /webhook (8080)     | (webhook_handler) |
+-----------+                      +--------+---------+
                                            |
                                     publish job
                                            |
                                   +--------v---------+
                                   | OCI Queue         |
                                   +--------+---------+
                                            |
                                     poll + consume
                                            |
                                   +--------v---------+
                                   | Worker Pool       |
                                   | (async, in-pod)   |
                                   +--+-----+-----+---+
                                      |     |     |
                          +-----------+  +--+--+  +-----------+
                          | Clone     |  | LLM |  | TMI API   |
                          | GitHub    |  | OCI |  | Create    |
                          | repo      |  | GenAI| | artifacts |
                          +-----------+  +-----+  +-----------+

Secrets loaded from OCI Vault at startup via workload identity.
```

## What This Design Does NOT Cover

- CI/CD pipeline for automated image builds
- Horizontal scaling / multiple replicas (single replica is sufficient for expected load)
- Monitoring/alerting beyond OCI Logging (already in TMI infra)
- DNS or Ingress for external access (not needed — internal ClusterIP only)
