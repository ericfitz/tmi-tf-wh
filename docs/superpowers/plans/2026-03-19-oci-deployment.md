# OCI Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy tmi-tf-wh as a containerized workload on an existing OKE cluster, following the TMI project's optional-addon pattern.

**Architecture:** Multi-stage Docker image built on Oracle Linux 9, deployed via Terraform as an optional Kubernetes Deployment + ClusterIP Service in the `tmi` namespace. OCI Queue for job dispatch, OCI Vault for secrets, workload identity for IAM.

**Tech Stack:** Python 3 / FastAPI / uvicorn, OCI SDK, LiteLLM, Terraform (OCI + Kubernetes providers), Docker (arm64)

**Spec:** `docs/superpowers/specs/2026-03-19-oci-deployment-design.md`

---

## File Map

### tmi-tf-wh repo (this repo)

| File | Action | Purpose |
|------|--------|---------|
| `Dockerfile` | Create | Multi-stage arm64 container build |
| `.dockerignore` | Create | Exclude dev files from build context |
| `tmi_tf/config.py` | Modify (lines 171-214) | Add instance principal support for OCI LLM credentials |
| `tests/test_config.py` | Modify | Add tests for new OCI credential methods |
| `deploy/terraform/*.tf` | Delete (10 files) | Remove old VM-based deployment |
| `deploy/terraform/.terraform.lock.hcl` | Delete | Remove old lock file |
| `deploy/tmi-tf-wh.service` | Delete | Remove old systemd unit |

### TMI repo (ericfitz/tmi) — separate repo, separate PR

| File | Action | Purpose |
|------|--------|---------|
| `terraform/modules/kubernetes/oci/k8s_resources.tf` | Modify | Add tmi-tf-wh Deployment, Service, ServiceAccount, ConfigMap |
| `terraform/modules/kubernetes/oci/variables.tf` | Modify | Add tmi-tf-wh variables |
| `terraform/environments/oci-public/main.tf` | Modify | Add OCIR repo, OCI Queue, IAM policy |
| `terraform/environments/oci-public/variables.tf` | Modify | Add tmi-tf-wh variables |
| `terraform/environments/oci-public/terraform.tfvars.example` | Modify | Add example config |
| `terraform/environments/oci-private/main.tf` | Modify | Same as oci-public (is_public=false for OCIR) |
| `terraform/environments/oci-private/variables.tf` | Modify | Add tmi-tf-wh variables |
| `terraform/environments/oci-private/terraform.tfvars.example` | Modify | Add example config |

---

## Task 1: Update `config.py` — OCI instance principal support

**Files:**
- Modify: `tmi_tf/config.py:171-214`
- Test: `tests/test_config.py`

This task updates `_oci_credentials_available()` and `get_oci_completion_kwargs()` to support OKE workload identity / instance principal authentication, falling back to `~/.oci/config`. Without this, LLM calls will fail in the container.

Also updates the warning message in `_validate_llm_credentials` to mention instance principal as a checked credential source.

**Note:** LiteLLM's OCI provider natively supports `oci_signer` objects (see `litellm/llms/oci/chat/transformation.py:_sign_with_oci_signer`), so passing the instance principal signer directly is the correct approach.

- [ ] **Step 1: Write failing test for `_oci_credentials_available` with instance principal**

Add to `tests/test_config.py` in class `TestOCIValidation`:

```python
def test_oci_credentials_available_checks_instance_principal(self):
    """_oci_credentials_available returns True when instance principal signer works."""
    with patch("pathlib.Path.exists", return_value=False):
        with patch(
            "urllib.request.urlopen", side_effect=Exception("connection refused")
        ):
            mock_signer = MagicMock()
            with patch(
                "oci.auth.signers.InstancePrincipalsSecurityTokenSigner",
                return_value=mock_signer,
            ):
                result = Config._oci_credentials_available()
                assert result is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_config.py::TestOCIValidation::test_oci_credentials_available_checks_instance_principal -v`
Expected: FAIL (current code doesn't try instance principal)

- [ ] **Step 3: Update `_oci_credentials_available` to try instance principal**

Replace the method in `tmi_tf/config.py` (lines 171-192):

```python
@staticmethod
def _oci_credentials_available() -> bool:
    """Check if OCI credentials are available.

    Checks in order: ~/.oci/config file, instance principal signer
    (works with OKE workload identity), IMDS metadata service.
    Returns True if any credential source is available.
    """
    import urllib.request

    # Check for OCI config file
    oci_config_path = Path.home() / ".oci" / "config"
    if oci_config_path.exists():
        return True

    # Check instance principal (OKE workload identity)
    try:
        from oci.auth.signers import InstancePrincipalsSecurityTokenSigner  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

        InstancePrincipalsSecurityTokenSigner()
        return True
    except Exception:
        pass

    # Check IMDS (OCI instance metadata service)
    try:
        req = urllib.request.Request(
            "http://169.254.169.254/opc/v2/instance/",
            headers={"Authorization": "Bearer Oracle"},
        )
        with urllib.request.urlopen(req, timeout=2):
            return True
    except Exception:
        return False
```

- [ ] **Step 4: Update warning message in `_validate_llm_credentials`**

In `tmi_tf/config.py`, update the warning at line 162 from:

```python
"OCI credentials not found via ~/.oci/config or IMDS. "
```

to:

```python
"OCI credentials not found via ~/.oci/config, instance principal, or IMDS. "
```

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/test_config.py::TestOCIValidation -v`
Expected: All tests PASS

- [ ] **Step 6: Write failing test for `get_oci_completion_kwargs` with instance principal**

Add a new test class in `tests/test_config.py`:

```python
class TestOCICompletionKwargs:
    @patch.dict(
        os.environ,
        {
            "LLM_PROVIDER": "oci",
            "OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test",
        },
        clear=False,
    )
    @patch("tmi_tf.config.Config._oci_credentials_available", return_value=True)
    def test_returns_empty_for_non_oci_provider(self, mock_creds):
        config = Config()
        config.llm_provider = "anthropic"
        result = config.get_oci_completion_kwargs()
        assert result == {}

    @patch.dict(
        os.environ,
        {
            "LLM_PROVIDER": "oci",
            "OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test",
        },
        clear=False,
    )
    @patch("tmi_tf.config.Config._oci_credentials_available", return_value=True)
    def test_uses_instance_principal_when_no_config_file(self, mock_creds):
        config = Config()
        mock_signer = MagicMock()
        mock_signer.region = "us-phoenix-1"
        with patch("pathlib.Path.exists", return_value=False):
            with patch(
                "oci.auth.signers.InstancePrincipalsSecurityTokenSigner",
                return_value=mock_signer,
            ):
                result = config.get_oci_completion_kwargs()
                assert result["oci_region"] == "us-phoenix-1"
                assert result["oci_compartment_id"] == "ocid1.compartment.oc1..test"
                assert result["oci_signer"] is mock_signer

    @patch.dict(
        os.environ,
        {
            "LLM_PROVIDER": "oci",
            "OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test",
        },
        clear=False,
    )
    @patch("tmi_tf.config.Config._oci_credentials_available", return_value=True)
    def test_falls_back_to_config_file(self, mock_creds):
        config = Config()
        mock_oci_config = {
            "region": "us-ashburn-1",
            "user": "ocid1.user.oc1..test",
            "fingerprint": "aa:bb:cc",
            "tenancy": "ocid1.tenancy.oc1..test",
            "key_file": "/path/to/key.pem",
        }
        with patch("pathlib.Path.exists", return_value=True):
            with patch(
                "oci.config.from_file", return_value=mock_oci_config
            ):
                result = config.get_oci_completion_kwargs()
                assert result["oci_region"] == "us-ashburn-1"
                assert result["oci_user"] == "ocid1.user.oc1..test"
                assert result["oci_fingerprint"] == "aa:bb:cc"
                assert result["oci_tenancy"] == "ocid1.tenancy.oc1..test"
                assert result["oci_key_file"] == "/path/to/key.pem"
                assert result["oci_compartment_id"] == "ocid1.compartment.oc1..test"
```

- [ ] **Step 7: Run test to verify it fails**

Run: `uv run pytest tests/test_config.py::TestOCICompletionKwargs -v`
Expected: FAIL (current code has no instance principal path)

- [ ] **Step 8: Update `get_oci_completion_kwargs` to support instance principal**

Replace the method in `tmi_tf/config.py` (lines 194-214):

```python
def get_oci_completion_kwargs(self) -> dict:
    """Return kwargs to pass to litellm.completion() for OCI provider.

    For non-OCI providers, returns an empty dict so callers can always
    unpack this into their completion() calls.

    Tries instance principal (OKE workload identity) first, then
    falls back to ~/.oci/config — matching vault_client._get_oci_signer().
    """
    if self.llm_provider != "oci":
        return {}

    oci_config_path = Path.home() / ".oci" / "config"
    if oci_config_path.exists():
        from oci.config import from_file as oci_from_file  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

        oci_config = oci_from_file(
            str(oci_config_path), self.oci_config_profile
        )
        return {
            "oci_region": oci_config.get("region", "us-ashburn-1"),
            "oci_user": oci_config["user"],
            "oci_fingerprint": oci_config["fingerprint"],
            "oci_tenancy": oci_config["tenancy"],
            "oci_key_file": oci_config["key_file"],
            "oci_compartment_id": self.oci_compartment_id,
        }

    # Instance principal (OKE workload identity)
    try:
        from oci.auth.signers import InstancePrincipalsSecurityTokenSigner  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

        signer = InstancePrincipalsSecurityTokenSigner()
        region = getattr(signer, "region", None) or "us-ashburn-1"
        return {
            "oci_region": region,
            "oci_compartment_id": self.oci_compartment_id,
            "oci_signer": signer,
        }
    except Exception as e:
        logger.error("No OCI credentials available for LLM calls: %s", e)
        return {}
```

- [ ] **Step 9: Run all config tests**

Run: `uv run pytest tests/test_config.py -v`
Expected: All tests PASS

- [ ] **Step 10: Run full test suite, lint, and type check**

Run: `uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/`
Expected: All pass

- [ ] **Step 11: Commit**

```bash
git add tmi_tf/config.py tests/test_config.py
git commit -m "feat: add OCI instance principal support for LLM credentials

get_oci_completion_kwargs() now tries instance principal signer
(OKE workload identity) when ~/.oci/config is not available.
_oci_credentials_available() also checks instance principal."
```

---

## Task 2: Create Dockerfile and .dockerignore

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`

- [ ] **Step 1: Create `.dockerignore`**

Create `.dockerignore`:

```
.venv/
.git/
.gitignore
.env
.env.*
__pycache__/
*.pyc
tests/
docs/
deploy/
*.egg-info/
.ruff_cache/
.pytest_cache/
.mypy_cache/
```

- [ ] **Step 2: Create `Dockerfile`**

Create `Dockerfile`:

```dockerfile
# Multi-stage Oracle Linux tmi-tf-wh build
# Builds a Python FastAPI webhook analyzer for OKE deployment
#
# Build: docker buildx build --platform linux/arm64 -t <tag> .
# Run:   docker run -p 8080:8080 <tag>

# Stage 1: Build environment
FROM container-registry.oracle.com/os/oraclelinux:9 AS builder

LABEL stage="builder"

# Install Python, pip, git, and build dependencies
RUN dnf -y update && \
    dnf -y install \
        python3 \
        python3-pip \
        python3-devel \
        gcc \
        git \
        ca-certificates && \
    dnf clean all && \
    rm -rf /var/cache/dnf

# Clone TMI Python client
ARG TMI_CLIENT_REPO=https://github.com/ericfitz/tmi-clients.git
ARG TMI_CLIENT_REF=main
RUN git clone --depth 1 --branch ${TMI_CLIENT_REF} ${TMI_CLIENT_REPO} /opt/tmi-clients

WORKDIR /app

# Upgrade pip to ensure PEP 517 build support (hatchling backend)
RUN pip3 install --no-cache-dir --upgrade pip

# Copy full source (pyproject.toml + tmi_tf package)
COPY pyproject.toml ./
COPY tmi_tf/ tmi_tf/

# Install the app and all dependencies
RUN pip3 install --no-cache-dir --prefix=/install .

# Stage 2: Runtime image
FROM container-registry.oracle.com/os/oraclelinux:9-slim

LABEL maintainer="TMI Security Team"
LABEL org.opencontainers.image.title="tmi-tf-wh"
LABEL org.opencontainers.image.description="TMI Terraform Webhook Analyzer"

ARG BUILD_DATE
ARG GIT_COMMIT
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${GIT_COMMIT}"

# Install runtime dependencies
RUN microdnf -y update && \
    microdnf -y install \
        python3 \
        git \
        ca-certificates && \
    microdnf clean all && \
    rm -rf /var/cache/yum

# Create non-root user with writable home directory
RUN groupadd -r tmi-tf && \
    useradd -r -g tmi-tf -m -d /home/tmi-tf -s /sbin/nologin tmi-tf

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy TMI Python client
COPY --from=builder /opt/tmi-clients/python-client-generated /opt/tmi-client

# Set environment
ENV HOME=/home/tmi-tf
ENV TMI_CLIENT_PATH=/opt/tmi-client
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

USER tmi-tf:tmi-tf
WORKDIR /home/tmi-tf

ENTRYPOINT ["python3", "-m", "uvicorn", "tmi_tf.server:app", "--host", "0.0.0.0", "--port", "8080"]
```

- [ ] **Step 3: Verify Dockerfile syntax**

Run: `docker buildx build --platform linux/arm64 --check -f Dockerfile .`

If `--check` is not available, verify with: `docker buildx build --platform linux/arm64 --progress=plain -f Dockerfile . 2>&1 | head -5`

This is a syntax-only check. A full build requires ARM build support and network access to Oracle Container Registry — it can be done separately.

- [ ] **Step 4: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "feat: add Dockerfile and .dockerignore for OKE deployment

Multi-stage build on Oracle Linux 9 / 9-slim for arm64.
Clones TMI Python client at build time. Runs as non-root tmi-tf user."
```

---

## Task 3: Delete old VM-based deployment files

**Files:**
- Delete: `deploy/terraform/main.tf`
- Delete: `deploy/terraform/compute.tf`
- Delete: `deploy/terraform/network.tf`
- Delete: `deploy/terraform/loadbalancer.tf`
- Delete: `deploy/terraform/queue.tf`
- Delete: `deploy/terraform/vault.tf`
- Delete: `deploy/terraform/iam.tf`
- Delete: `deploy/terraform/logging.tf`
- Delete: `deploy/terraform/variables.tf`
- Delete: `deploy/terraform/outputs.tf`
- Delete: `deploy/terraform/.terraform.lock.hcl`
- Delete: `deploy/tmi-tf-wh.service`

- [ ] **Step 1: Delete all deploy files**

```bash
git rm -r deploy/
```

- [ ] **Step 2: Run lint and tests to confirm nothing depends on deleted files**

Run: `uv run ruff check tmi_tf/ tests/ && uv run pytest tests/`
Expected: All pass (no code imports from deploy/)

- [ ] **Step 3: Commit**

```bash
git commit -m "chore: remove old VM-based deployment files

Replaced by OKE-based deployment in the TMI repo
(terraform/modules/kubernetes/oci/)."
```

---

## Task 4: Add tmi-tf-wh Kubernetes resources to TMI repo

**Repo:** `ericfitz/tmi` (separate clone needed)
**Files:**
- Modify: `terraform/modules/kubernetes/oci/variables.tf`
- Modify: `terraform/modules/kubernetes/oci/k8s_resources.tf`

- [ ] **Step 1: Add variables to `terraform/modules/kubernetes/oci/variables.tf`**

Append to the end of the file (before the closing, after the last variable):

```hcl
# ---------------------------------------------------------------------------
# tmi-tf-wh Webhook Analyzer (optional)
# ---------------------------------------------------------------------------
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

variable "tmi_tf_wh_cpu_request" {
  description = "CPU request for tmi-tf-wh pod"
  type        = string
  default     = "500m"
}

variable "tmi_tf_wh_memory_request" {
  description = "Memory request for tmi-tf-wh pod"
  type        = string
  default     = "1Gi"
}

variable "tmi_tf_wh_cpu_limit" {
  description = "CPU limit for tmi-tf-wh pod"
  type        = string
  default     = "2"
}

variable "tmi_tf_wh_memory_limit" {
  description = "Memory limit for tmi-tf-wh pod"
  type        = string
  default     = "4Gi"
}

variable "tmi_tf_wh_extra_env_vars" {
  description = "Additional environment variables for tmi-tf-wh"
  type        = map(string)
  default     = {}
}
```

- [ ] **Step 2: Add K8s resources to `terraform/modules/kubernetes/oci/k8s_resources.tf`**

Append to the end of the file (after the TMI-UX section):

```hcl
# ============================================================================
# Optional: tmi-tf-wh Webhook Analyzer (when enabled)
# ============================================================================

# ServiceAccount for tmi-tf-wh (enables OKE Workload Identity)
resource "kubernetes_service_account_v1" "tmi_tf_wh" {
  count = var.tmi_tf_wh_enabled ? 1 : 0

  metadata {
    name      = "tmi-tf-wh"
    namespace = kubernetes_namespace_v1.tmi.metadata[0].name
    labels = {
      app        = "tmi-tf-wh"
      managed_by = "terraform"
    }
  }

  automount_service_account_token = true
}

# ConfigMap for tmi-tf-wh (non-sensitive environment variables)
resource "kubernetes_config_map_v1" "tmi_tf_wh" {
  count = var.tmi_tf_wh_enabled ? 1 : 0

  metadata {
    name      = "tmi-tf-wh-config"
    namespace = kubernetes_namespace_v1.tmi.metadata[0].name
  }

  data = merge(
    {
      LLM_PROVIDER       = "oci"
      OCI_COMPARTMENT_ID = var.compartment_id
      QUEUE_OCID         = var.tmi_tf_wh_queue_ocid
      VAULT_OCID         = var.vault_ocid
      TMI_SERVER_URL     = "http://tmi-api:8080"
      TMI_OAUTH_IDP      = "tmi"
      TMI_CLIENT_PATH    = "/opt/tmi-client"
      MAX_CONCURRENT_JOBS = "3"
      JOB_TIMEOUT         = "3600"
      SERVER_PORT          = "8080"
    },
    var.tmi_tf_wh_extra_env_vars
  )
}

# tmi-tf-wh Deployment
resource "kubernetes_deployment_v1" "tmi_tf_wh" {
  count = var.tmi_tf_wh_enabled ? 1 : 0

  wait_for_rollout = false

  metadata {
    name      = "tmi-tf-wh"
    namespace = kubernetes_namespace_v1.tmi.metadata[0].name
    labels = {
      app       = "tmi-tf-wh"
      component = "webhook-analyzer"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "tmi-tf-wh"
      }
    }

    strategy {
      type = "RollingUpdate"
      rolling_update {
        max_unavailable = "1"
        max_surge       = "1"
      }
    }

    template {
      metadata {
        labels = {
          app       = "tmi-tf-wh"
          component = "webhook-analyzer"
        }
      }

      spec {
        service_account_name            = kubernetes_service_account_v1.tmi_tf_wh[0].metadata[0].name
        automount_service_account_token = true

        container {
          name  = "tmi-tf-wh"
          image = var.tmi_tf_wh_image_url

          port {
            name           = "http"
            container_port = 8080
            protocol       = "TCP"
          }

          env_from {
            config_map_ref {
              name = kubernetes_config_map_v1.tmi_tf_wh[0].metadata[0].name
            }
          }

          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = "http"
            }
            initial_delay_seconds = 60
            period_seconds        = 30
            timeout_seconds       = 10
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = "http"
            }
            initial_delay_seconds = 10
            period_seconds        = 10
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          resources {
            requests = {
              cpu    = var.tmi_tf_wh_cpu_request
              memory = var.tmi_tf_wh_memory_request
            }
            limits = {
              cpu    = var.tmi_tf_wh_cpu_limit
              memory = var.tmi_tf_wh_memory_limit
            }
          }
        }

        volume {
          name = "tmp"
          empty_dir {}
        }

        termination_grace_period_seconds = 60
        restart_policy                   = "Always"
      }
    }
  }
}

# tmi-tf-wh ClusterIP Service (internal only)
resource "kubernetes_service_v1" "tmi_tf_wh" {
  count = var.tmi_tf_wh_enabled ? 1 : 0

  metadata {
    name      = "tmi-tf-wh"
    namespace = kubernetes_namespace_v1.tmi.metadata[0].name
    labels = {
      app       = "tmi-tf-wh"
      component = "webhook-analyzer"
    }
  }

  spec {
    selector = {
      app = "tmi-tf-wh"
    }

    port {
      name        = "http"
      port        = 8080
      target_port = 8080
      protocol    = "TCP"
    }

    type = "ClusterIP"
  }
}
```

- [ ] **Step 3: Validate Terraform syntax**

Run from `terraform/modules/kubernetes/oci/`:

```bash
terraform fmt -check
terraform validate
```

Expected: No errors

- [ ] **Step 4: Commit**

```bash
git add terraform/modules/kubernetes/oci/variables.tf terraform/modules/kubernetes/oci/k8s_resources.tf
git commit -m "feat: add optional tmi-tf-wh webhook analyzer K8s resources

Adds Deployment, ClusterIP Service, ServiceAccount, and ConfigMap
for tmi-tf-wh, gated by tmi_tf_wh_enabled variable.
Follows same pattern as tmi_ux_enabled."
```

---

## Task 5: Add OCI resources and pass-through in oci-public environment

**Repo:** `ericfitz/tmi`
**Files:**
- Modify: `terraform/environments/oci-public/main.tf`
- Modify: `terraform/environments/oci-public/variables.tf`
- Modify: `terraform/environments/oci-public/terraform.tfvars.example`

- [ ] **Step 1: Add variables to `terraform/environments/oci-public/variables.tf`**

Append before the `tags` variable:

```hcl
# ---------------------------------------------------------------------------
# tmi-tf-wh Webhook Analyzer (optional)
# ---------------------------------------------------------------------------
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

variable "tmi_tf_wh_extra_env_vars" {
  description = "Additional environment variables for tmi-tf-wh"
  type        = map(string)
  default     = {}
}
```

- [ ] **Step 2: Add OCIR repo, Queue, and IAM to `terraform/environments/oci-public/main.tf`**

Add after the existing `oci_artifacts_container_repository.redis` resource:

```hcl
resource "oci_artifacts_container_repository" "tmi_tf_wh" {
  count          = var.tmi_tf_wh_enabled ? 1 : 0
  compartment_id = var.compartment_id
  display_name   = "${var.name_prefix}/tmi-tf-wh"
  is_public      = true
}
```

Add after the logging module block:

```hcl
# ---------------------------------------------------------------------------
# tmi-tf-wh Queue (optional — enabled when tmi_tf_wh_enabled is true)
# ---------------------------------------------------------------------------
resource "oci_queue_queue" "tmi_tf_wh" {
  count                            = var.tmi_tf_wh_enabled ? 1 : 0
  compartment_id                   = var.compartment_id
  display_name                     = "${var.name_prefix}-tf-wh-queue"
  visibility_in_seconds            = 3600
  retention_in_seconds             = 86400
  dead_letter_queue_delivery_count = 3
}
```

- [ ] **Step 3: Add pass-through variables to the kubernetes module call**

In the `module "kubernetes"` block, add alongside the existing `tmi_ux_enabled` / `tmi_ux_image_url` lines:

```hcl
  # tmi-tf-wh Webhook Analyzer configuration (optional)
  tmi_tf_wh_enabled        = var.tmi_tf_wh_enabled
  tmi_tf_wh_image_url      = var.tmi_tf_wh_image_url
  tmi_tf_wh_queue_ocid     = var.tmi_tf_wh_enabled ? oci_queue_queue.tmi_tf_wh[0].id : ""
  tmi_tf_wh_extra_env_vars = var.tmi_tf_wh_extra_env_vars
```

- [ ] **Step 4: Add queue and Generative AI IAM permissions to existing vault_access policy**

The existing `oci_identity_policy.vault_access` resource currently has a plain list for `statements`. Wrap it in `concat()` to conditionally add tmi-tf-wh permissions.

**Before** (existing code):
```hcl
  statements = [
    "Allow dynamic-group ${oci_identity_dynamic_group.tmi_oke.name} to read secret-family in compartment id ${var.compartment_id}",
    "Allow dynamic-group ${oci_identity_dynamic_group.tmi_oke.name} to use keys in compartment id ${var.compartment_id}"
  ]
```

**After:**
```hcl
  statements = concat(
    [
      "Allow dynamic-group ${oci_identity_dynamic_group.tmi_oke.name} to read secret-family in compartment id ${var.compartment_id}",
      "Allow dynamic-group ${oci_identity_dynamic_group.tmi_oke.name} to use keys in compartment id ${var.compartment_id}",
    ],
    var.tmi_tf_wh_enabled ? [
      "Allow dynamic-group ${oci_identity_dynamic_group.tmi_oke.name} to use queues in compartment id ${var.compartment_id} where target.queue.id = '${oci_queue_queue.tmi_tf_wh[0].id}'",
      "Allow dynamic-group ${oci_identity_dynamic_group.tmi_oke.name} to manage queue-messages in compartment id ${var.compartment_id} where target.queue.id = '${oci_queue_queue.tmi_tf_wh[0].id}'",
      "Allow dynamic-group ${oci_identity_dynamic_group.tmi_oke.name} to use generative-ai-family in compartment id ${var.compartment_id}",
    ] : []
  )
```

- [ ] **Step 5: Add example to `terraform/environments/oci-public/terraform.tfvars.example`**

Append before the `# Tags` section:

```hcl
# ---------------------------------------------------------------------------
# Optional: TMI-TF-WH Webhook Analyzer
# ---------------------------------------------------------------------------
# tmi_tf_wh_enabled   = true
# tmi_tf_wh_image_url = "<region>.ocir.io/<namespace>/tmi/tmi-tf-wh:latest"
```

- [ ] **Step 6: Validate Terraform syntax**

Run from `terraform/environments/oci-public/`:

```bash
terraform fmt -check
terraform validate
```

Note: `terraform validate` may require initialized providers. If it fails on provider init, `terraform fmt -check` alone is sufficient for syntax validation.

- [ ] **Step 7: Commit**

```bash
git add terraform/environments/oci-public/
git commit -m "feat(oci-public): add optional tmi-tf-wh OCIR repo, queue, and IAM

Adds container registry, OCI Queue, and queue IAM permissions
for tmi-tf-wh, all gated by tmi_tf_wh_enabled variable."
```

---

## Task 6: Add OCI resources and pass-through in oci-private environment

**Repo:** `ericfitz/tmi`
**Files:**
- Modify: `terraform/environments/oci-private/main.tf`
- Modify: `terraform/environments/oci-private/variables.tf`
- Modify: `terraform/environments/oci-private/terraform.tfvars.example`

This task mirrors Task 5 exactly, with one difference: `is_public = false` for the OCIR container repository.

- [ ] **Step 1: Add variables to `terraform/environments/oci-private/variables.tf`**

Same variables as Task 5, Step 1 — append the tmi-tf-wh variables block.

- [ ] **Step 2: Add OCIR repo (is_public=false), Queue, and IAM to `terraform/environments/oci-private/main.tf`**

Same resources as Task 5, Steps 2-4, except:

```hcl
resource "oci_artifacts_container_repository" "tmi_tf_wh" {
  count          = var.tmi_tf_wh_enabled ? 1 : 0
  compartment_id = var.compartment_id
  display_name   = "${var.name_prefix}/tmi-tf-wh"
  is_public      = false  # Private access only
}
```

The Queue resource, kubernetes module pass-through, and IAM policy changes are identical to oci-public.

- [ ] **Step 3: Add example to `terraform/environments/oci-private/terraform.tfvars.example`**

Same as Task 5, Step 5.

- [ ] **Step 4: Validate Terraform syntax**

Run from `terraform/environments/oci-private/`:

```bash
terraform fmt -check
```

- [ ] **Step 5: Commit**

```bash
git add terraform/environments/oci-private/
git commit -m "feat(oci-private): add optional tmi-tf-wh OCIR repo, queue, and IAM

Mirrors oci-public configuration with is_public=false for OCIR."
```

---

## Task 7: Final validation

- [ ] **Step 1: Run full tmi-tf-wh test suite**

Run from the tmi-tf-wh repo:

```bash
uv run ruff check tmi_tf/ tests/
uv run ruff format --check tmi_tf/ tests/
uv run pyright
uv run pytest tests/
```

Expected: All pass

- [ ] **Step 2: Run Terraform format check on all TMI changes**

Run from the TMI repo:

```bash
terraform fmt -check -recursive terraform/
```

Expected: No formatting issues

- [ ] **Step 3: Verify no regressions in TMI Terraform**

Review that existing resources (tmi-api, redis, tmi-ux) are unchanged by running:

```bash
git diff terraform/modules/kubernetes/oci/k8s_resources.tf | head -20
```

Confirm only additions (no modifications to existing resources).
