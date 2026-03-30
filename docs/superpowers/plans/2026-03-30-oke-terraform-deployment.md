# OKE Terraform Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a Terraform module that deploys tmi-tf-wh to an OKE cluster with OCI Queue, Vault, API Gateway, and a public Load Balancer, plus the Python code changes needed for in-cluster OCI service endpoint resolution.

**Architecture:** The deployer provides an existing VCN with subnets. Terraform creates an OKE cluster (ARM A1 Flex nodes), OCI Queue, OCI Vault with secrets, a dynamic group + IAM policies for workload identity, an OCIR repository, a public API Gateway routing to a K8s LoadBalancer Service, and K8s manifests for the tmi-tf-wh Deployment + ServiceAccount. Python code is updated so `QueueClient`, `VaultsClient`, and `SecretsClient` accept explicit `service_endpoint` URLs from env vars, since the OCI SDK cannot auto-discover endpoints from inside OKE pods.

**Tech Stack:** Terraform (OCI provider), Kubernetes provider, Python 3.12, OCI SDK, FastAPI

---

## File Structure

### Terraform files (new directory `infra/`)

| File | Responsibility |
|------|---------------|
| `infra/versions.tf` | Required providers (oci, kubernetes) and terraform version |
| `infra/variables.tf` | All input variables (VCN OCID, subnet OCIDs, compartment, region, etc.) |
| `infra/oke.tf` | OKE cluster + node pool |
| `infra/queue.tf` | OCI Queue |
| `infra/vault.tf` | OCI Vault + master key + secret resources |
| `infra/iam.tf` | Dynamic group + IAM policies for workload identity |
| `infra/ocir.tf` | OCIR container repository |
| `infra/api_gateway.tf` | API Gateway + deployment routing to LB |
| `infra/k8s.tf` | K8s Deployment, Service, ServiceAccount, namespace |
| `infra/outputs.tf` | Terraform outputs (cluster OCID, queue OCID, LB IP, gateway URL, etc.) |
| `infra/terraform.tfvars.example` | Example tfvars for deployers |

### Python code changes (existing files)

| File | Change |
|------|--------|
| `tmi_tf/config.py` | Add `queue_endpoint`, `vault_endpoint`, `secrets_endpoint` env vars |
| `tmi_tf/vault_client.py` | Pass `service_endpoint` to `VaultsClient` and `SecretsClient` when configured |
| `tmi_tf/queue_client.py` | Pass `service_endpoint` to OCI `QueueClient` when configured |
| `tests/test_config.py` | Tests for new endpoint env vars |
| `tests/test_vault_client.py` | Tests for service_endpoint passthrough |
| `tests/test_queue_client.py` | Tests for service_endpoint passthrough |

---

## Part 1: Python Code Changes (service endpoint support)

### Task 1: Add service endpoint env vars to Config

**Files:**
- Modify: `tmi_tf/config.py:117-119`
- Modify: `tests/test_config.py`

- [ ] **Step 1: Write failing tests for new config fields**

Add to `tests/test_config.py`:

```python
class TestServiceEndpointConfig:
    @patch.dict(
        os.environ,
        {
            "LLM_PROVIDER": "anthropic",
            "ANTHROPIC_API_KEY": "test",
            "QUEUE_ENDPOINT": "https://cell-1.queue.oc1.us-ashburn-1.oci.oraclecloud.com",
            "VAULT_ENDPOINT": "https://vaults.us-ashburn-1.oci.oraclecloud.com",
            "SECRETS_ENDPOINT": "https://secrets.vaults.us-ashburn-1.oci.oraclecloud.com",
        },
        clear=False,
    )
    def test_service_endpoints_loaded(self):
        config = Config()
        assert config.queue_endpoint == "https://cell-1.queue.oc1.us-ashburn-1.oci.oraclecloud.com"
        assert config.vault_endpoint == "https://vaults.us-ashburn-1.oci.oraclecloud.com"
        assert config.secrets_endpoint == "https://secrets.vaults.us-ashburn-1.oci.oraclecloud.com"

    @patch.dict(
        os.environ,
        {"LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"},
        clear=False,
    )
    def test_service_endpoints_default_none(self):
        config = Config()
        assert config.queue_endpoint is None
        assert config.vault_endpoint is None
        assert config.secrets_endpoint is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_config.py::TestServiceEndpointConfig -v`
Expected: FAIL with `AttributeError: 'Config' object has no attribute 'queue_endpoint'`

- [ ] **Step 3: Add endpoint fields to Config**

In `tmi_tf/config.py`, add after line 119 (`self.tmi_client_path`):

```python
        # OCI service endpoints (required for in-cluster OKE access)
        self.queue_endpoint: Optional[str] = os.getenv("QUEUE_ENDPOINT") or None
        self.vault_endpoint: Optional[str] = os.getenv("VAULT_ENDPOINT") or None
        self.secrets_endpoint: Optional[str] = os.getenv("SECRETS_ENDPOINT") or None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_config.py::TestServiceEndpointConfig -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tmi_tf/config.py tests/test_config.py
git commit -m "feat: add OCI service endpoint config vars for OKE deployment"
```

---

### Task 2: Pass service_endpoint to VaultsClient and SecretsClient

**Files:**
- Modify: `tmi_tf/vault_client.py:47-60`
- Modify: `tests/test_vault_client.py`

- [ ] **Step 1: Write failing tests for endpoint passthrough**

Add to `tests/test_vault_client.py`:

```python
class TestServiceEndpoints:
    @patch("tmi_tf.vault_client._get_oci_signer")
    def test_vaults_client_uses_service_endpoint(self, mock_signer):
        mock_signer.return_value = MagicMock()
        with patch.dict(os.environ, {"VAULT_ENDPOINT": "https://vaults.us-ashburn-1.oci.oraclecloud.com"}):
            with patch("tmi_tf.vault_client.VaultsClient") as mock_cls:
                from tmi_tf.vault_client import _get_vaults_client
                _get_vaults_client()
                mock_cls.assert_called_once_with(
                    config={},
                    signer=mock_signer.return_value,
                    service_endpoint="https://vaults.us-ashburn-1.oci.oraclecloud.com",
                )

    @patch("tmi_tf.vault_client._get_oci_signer")
    def test_vaults_client_no_endpoint_when_unset(self, mock_signer):
        mock_signer.return_value = MagicMock()
        with patch.dict(os.environ, {}, clear=False):
            # Ensure VAULT_ENDPOINT is not set
            os.environ.pop("VAULT_ENDPOINT", None)
            with patch("tmi_tf.vault_client.VaultsClient") as mock_cls:
                from tmi_tf.vault_client import _get_vaults_client
                _get_vaults_client()
                mock_cls.assert_called_once_with(
                    config={},
                    signer=mock_signer.return_value,
                )

    @patch("tmi_tf.vault_client._get_oci_signer")
    def test_secrets_client_uses_service_endpoint(self, mock_signer):
        mock_signer.return_value = MagicMock()
        with patch.dict(os.environ, {"SECRETS_ENDPOINT": "https://secrets.vaults.us-ashburn-1.oci.oraclecloud.com"}):
            with patch("tmi_tf.vault_client.SecretsClient") as mock_cls:
                from tmi_tf.vault_client import _get_secrets_client
                _get_secrets_client()
                mock_cls.assert_called_once_with(
                    config={},
                    signer=mock_signer.return_value,
                    service_endpoint="https://secrets.vaults.us-ashburn-1.oci.oraclecloud.com",
                )

    @patch("tmi_tf.vault_client._get_oci_signer")
    def test_secrets_client_no_endpoint_when_unset(self, mock_signer):
        mock_signer.return_value = MagicMock()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SECRETS_ENDPOINT", None)
            with patch("tmi_tf.vault_client.SecretsClient") as mock_cls:
                from tmi_tf.vault_client import _get_secrets_client
                _get_secrets_client()
                mock_cls.assert_called_once_with(
                    config={},
                    signer=mock_signer.return_value,
                )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_vault_client.py::TestServiceEndpoints -v`
Expected: FAIL — the current code doesn't pass `service_endpoint`

- [ ] **Step 3: Update vault_client.py to pass service_endpoint**

Replace `_get_secrets_client` and `_get_vaults_client` in `tmi_tf/vault_client.py`:

```python
def _get_secrets_client():  # type: ignore[return]
    """Create and return an OCI SecretsClient using the appropriate signer."""
    from oci.secrets import SecretsClient  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

    signer = _get_oci_signer()
    kwargs: dict = {"config": {}, "signer": signer}
    endpoint = os.getenv("SECRETS_ENDPOINT")
    if endpoint:
        kwargs["service_endpoint"] = endpoint
    return SecretsClient(**kwargs)


def _get_vaults_client():  # type: ignore[return]
    """Create and return an OCI VaultsClient using the appropriate signer."""
    from oci.vault import VaultsClient  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

    signer = _get_oci_signer()
    kwargs: dict = {"config": {}, "signer": signer}
    endpoint = os.getenv("VAULT_ENDPOINT")
    if endpoint:
        kwargs["service_endpoint"] = endpoint
    return VaultsClient(**kwargs)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_vault_client.py -v`
Expected: All PASS (existing + new)

- [ ] **Step 5: Commit**

```bash
git add tmi_tf/vault_client.py tests/test_vault_client.py
git commit -m "feat: support OCI service endpoint override for vault/secrets clients"
```

---

### Task 3: Pass service_endpoint to QueueClient

**Files:**
- Modify: `tmi_tf/queue_client.py:21-33`
- Modify: `tests/test_queue_client.py`

- [ ] **Step 1: Write failing tests for endpoint passthrough**

Add to `tests/test_queue_client.py`:

```python
class TestQueueServiceEndpoint:
    @patch("tmi_tf.queue_client.QueueClient._get_client")
    def test_get_client_uses_service_endpoint(self, mock_get: MagicMock) -> None:
        """When QUEUE_ENDPOINT is set, _get_client passes service_endpoint to OCI SDK."""
        import os
        from unittest.mock import patch as mock_patch

        with mock_patch.dict(os.environ, {"QUEUE_ENDPOINT": "https://cell-1.queue.oc1.us-ashburn-1.oci.oraclecloud.com"}):
            with mock_patch("tmi_tf.queue_client.QueueClient._init_oci_client") as mock_init:
                mock_init.return_value = MagicMock()
                qc = QueueClient(queue_ocid="ocid1.queue.oc1..test")
                qc._client = None  # force re-init
                qc._get_client()
                mock_init.assert_called_once_with(
                    "https://cell-1.queue.oc1.us-ashburn-1.oci.oraclecloud.com"
                )

    @patch("tmi_tf.queue_client.QueueClient._get_client")
    def test_get_client_no_endpoint_when_unset(self, mock_get: MagicMock) -> None:
        """When QUEUE_ENDPOINT is not set, _get_client passes None."""
        import os
        from unittest.mock import patch as mock_patch

        with mock_patch.dict(os.environ, {}, clear=False):
            os.environ.pop("QUEUE_ENDPOINT", None)
            with mock_patch("tmi_tf.queue_client.QueueClient._init_oci_client") as mock_init:
                mock_init.return_value = MagicMock()
                qc = QueueClient(queue_ocid="ocid1.queue.oc1..test")
                qc._client = None
                qc._get_client()
                mock_init.assert_called_once_with(None)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_queue_client.py::TestQueueServiceEndpoint -v`
Expected: FAIL — `_init_oci_client` doesn't exist

- [ ] **Step 3: Update queue_client.py to pass service_endpoint**

Replace `_get_client` in `tmi_tf/queue_client.py`:

```python
    def _get_client(self):  # type: ignore[return]
        """Lazy-initialize and return the OCI QueueClient."""
        if self._client is None:
            endpoint = os.getenv("QUEUE_ENDPOINT")
            self._client = self._init_oci_client(endpoint)
        return self._client

    @staticmethod
    def _init_oci_client(service_endpoint: str | None):  # type: ignore[return]
        """Create an OCI QueueClient with optional service_endpoint."""
        from oci.queue import QueueClient as OCIQueueClient  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

        from tmi_tf.vault_client import _get_oci_signer

        signer = _get_oci_signer()
        kwargs: dict = {"config": {}, "signer": signer}
        if service_endpoint:
            kwargs["service_endpoint"] = service_endpoint
        return OCIQueueClient(**kwargs)
```

Also add `import os` at the top of `queue_client.py`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_queue_client.py -v`
Expected: All PASS

- [ ] **Step 5: Run full test suite, lint, type check**

Run: `uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/queue_client.py tests/test_queue_client.py
git commit -m "feat: support OCI service endpoint override for queue client"
```

---

## Part 2: Terraform Infrastructure

### Task 4: Terraform scaffolding — versions and variables

**Files:**
- Create: `infra/versions.tf`
- Create: `infra/variables.tf`
- Create: `infra/terraform.tfvars.example`

- [ ] **Step 1: Create `infra/versions.tf`**

```hcl
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 6.0.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.25.0"
    }
  }
}

provider "oci" {
  region = var.region
}

provider "kubernetes" {
  host                   = oci_containerengine_cluster.this.endpoints[0].kubernetes
  cluster_ca_certificate = base64decode(oci_containerengine_cluster.this.endpoints[0].public_endpoint != "" ? data.oci_containerengine_cluster_kube_config.this.content : "")
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "oci"
    args = [
      "ce", "cluster", "generate-token",
      "--cluster-id", oci_containerengine_cluster.this.id,
      "--region", var.region,
    ]
  }
}

data "oci_containerengine_cluster_kube_config" "this" {
  cluster_id = oci_containerengine_cluster.this.id
}

data "oci_identity_tenancy" "this" {
  tenancy_id = var.tenancy_ocid
}
```

- [ ] **Step 2: Create `infra/variables.tf`**

```hcl
# --- Required: deployer must set these ---

variable "tenancy_ocid" {
  description = "OCID of the OCI tenancy"
  type        = string
}

variable "compartment_ocid" {
  description = "OCID of the compartment to deploy into"
  type        = string
}

variable "region" {
  description = "OCI region (e.g. us-ashburn-1)"
  type        = string
}

variable "vcn_id" {
  description = "OCID of the existing VCN"
  type        = string
}

variable "subnet_id_oke_api" {
  description = "OCID of the subnet for the OKE API endpoint (regional, private or public)"
  type        = string
}

variable "subnet_id_oke_nodes" {
  description = "OCID of the private subnet for OKE worker nodes"
  type        = string
}

variable "subnet_id_oke_lb" {
  description = "OCID of the public subnet for the K8s LoadBalancer service"
  type        = string
}

variable "subnet_id_api_gateway" {
  description = "OCID of the public subnet for the API Gateway"
  type        = string
}

# --- Optional with defaults ---

variable "cluster_name" {
  description = "Name for the OKE cluster"
  type        = string
  default     = "tmi-tf-wh"
}

variable "node_shape" {
  description = "Shape for OKE node pool instances"
  type        = string
  default     = "VM.Standard.A1.Flex"
}

variable "node_ocpus" {
  description = "Number of OCPUs per node"
  type        = number
  default     = 2
}

variable "node_memory_gb" {
  description = "Memory in GB per node"
  type        = number
  default     = 12
}

variable "node_count" {
  description = "Number of nodes in the node pool"
  type        = number
  default     = 2
}

variable "node_image_id" {
  description = "OCID of the OKE node image (Oracle Linux aarch64). If empty, latest is used."
  type        = string
  default     = ""
}

variable "app_image_tag" {
  description = "Container image tag for tmi-tf-wh (e.g. 'latest' or a git SHA)"
  type        = string
  default     = "latest"
}

variable "k8s_namespace" {
  description = "Kubernetes namespace for the deployment"
  type        = string
  default     = "tmi-tf"
}

variable "llm_provider" {
  description = "LLM provider to use (anthropic, openai, xai, gemini, oci)"
  type        = string
  default     = "oci"
}

variable "tmi_server_url" {
  description = "TMI API server URL"
  type        = string
  default     = "https://api.tmi.dev"
}

variable "max_concurrent_jobs" {
  description = "Maximum concurrent analysis jobs"
  type        = number
  default     = 3
}
```

- [ ] **Step 3: Create `infra/terraform.tfvars.example`**

```hcl
# Required — provide your own values
tenancy_ocid          = "ocid1.tenancy.oc1..example"
compartment_ocid      = "ocid1.compartment.oc1..example"
region                = "us-ashburn-1"
vcn_id                = "ocid1.vcn.oc1.iad.example"
subnet_id_oke_api     = "ocid1.subnet.oc1.iad.example_api"
subnet_id_oke_nodes   = "ocid1.subnet.oc1.iad.example_nodes"
subnet_id_oke_lb      = "ocid1.subnet.oc1.iad.example_lb"
subnet_id_api_gateway = "ocid1.subnet.oc1.iad.example_apigw"

# Optional — uncomment to override defaults
# cluster_name        = "tmi-tf-wh"
# node_shape          = "VM.Standard.A1.Flex"
# node_ocpus          = 2
# node_memory_gb      = 12
# node_count          = 2
# node_image_id       = "ocid1.image.oc1.iad.example"
# app_image_tag       = "latest"
# k8s_namespace       = "tmi-tf"
# llm_provider        = "oci"
# tmi_server_url      = "https://api.tmi.dev"
# max_concurrent_jobs = 3
```

- [ ] **Step 4: Commit**

```bash
git add infra/versions.tf infra/variables.tf infra/terraform.tfvars.example
git commit -m "feat(infra): add terraform scaffolding — providers, variables, example tfvars"
```

---

### Task 5: OKE Cluster and Node Pool

**Files:**
- Create: `infra/oke.tf`

- [ ] **Step 1: Create `infra/oke.tf`**

```hcl
# Fetch latest supported OKE Kubernetes version
data "oci_containerengine_cluster_option" "this" {
  cluster_option_id = "all"
  compartment_id    = var.compartment_ocid
}

locals {
  # Latest Kubernetes version from OKE options
  k8s_version = data.oci_containerengine_cluster_option.this.kubernetes_versions[
    length(data.oci_containerengine_cluster_option.this.kubernetes_versions) - 1
  ]
}

resource "oci_containerengine_cluster" "this" {
  compartment_id     = var.compartment_ocid
  kubernetes_version = local.k8s_version
  name               = var.cluster_name
  vcn_id             = var.vcn_id

  endpoint_config {
    is_public_ip_enabled = true
    subnet_id            = var.subnet_id_oke_api
  }

  options {
    service_lb_subnet_ids = [var.subnet_id_oke_lb]
  }

  type = "ENHANCED_CLUSTER"
}

# Fetch latest aarch64 OKE node image if not provided
data "oci_containerengine_node_pool_option" "this" {
  node_pool_option_id = oci_containerengine_cluster.this.id
  compartment_id      = var.compartment_ocid
}

locals {
  # Use provided image ID or pick latest aarch64 Oracle Linux image
  node_image_id = var.node_image_id != "" ? var.node_image_id : [
    for src in data.oci_containerengine_node_pool_option.this.sources :
    src.image_id
    if can(regex("aarch64", src.source_name)) && can(regex("Oracle-Linux", src.source_name))
  ][0]
}

resource "oci_containerengine_node_pool" "this" {
  cluster_id         = oci_containerengine_cluster.this.id
  compartment_id     = var.compartment_ocid
  kubernetes_version = local.k8s_version
  name               = "${var.cluster_name}-pool"

  node_shape = var.node_shape

  node_shape_config {
    ocpus         = var.node_ocpus
    memory_in_gbs = var.node_memory_gb
  }

  node_source_details {
    image_id    = local.node_image_id
    source_type = "IMAGE"
  }

  node_config_details {
    size = var.node_count

    placement_configs {
      availability_domain = data.oci_identity_availability_domains.this.availability_domains[0].name
      subnet_id           = var.subnet_id_oke_nodes
    }
  }
}

data "oci_identity_availability_domains" "this" {
  compartment_id = var.tenancy_ocid
}
```

- [ ] **Step 2: Commit**

```bash
git add infra/oke.tf
git commit -m "feat(infra): add OKE cluster and ARM A1 Flex node pool"
```

---

### Task 6: OCI Queue

**Files:**
- Create: `infra/queue.tf`

- [ ] **Step 1: Create `infra/queue.tf`**

```hcl
resource "oci_queue_queue" "this" {
  compartment_id              = var.compartment_ocid
  display_name                = "${var.cluster_name}-jobs"
  visibility_in_seconds       = 900
  timeout_in_seconds          = 3600
  dead_letter_queue_delivery_count = 3
  retention_in_seconds        = 86400

  freeform_tags = {
    "app" = "tmi-tf-wh"
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add infra/queue.tf
git commit -m "feat(infra): add OCI Queue for job dispatch"
```

---

### Task 7: OCI Vault with Master Key and Secrets

**Files:**
- Create: `infra/vault.tf`

- [ ] **Step 1: Create `infra/vault.tf`**

```hcl
resource "oci_kms_vault" "this" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.cluster_name}-vault"
  vault_type     = "DEFAULT"

  freeform_tags = {
    "app" = "tmi-tf-wh"
  }
}

resource "oci_kms_key" "master" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.cluster_name}-master-key"

  key_shape {
    algorithm = "AES"
    length    = 32
  }

  management_endpoint = oci_kms_vault.this.management_endpoint

  protection_mode = "SOFTWARE"
}

# Secret shells — deployer populates values after apply via OCI CLI or Console
resource "oci_vault_secret" "webhook_secret" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.this.id
  key_id         = oci_kms_key.master.id
  secret_name    = "webhook-secret"

  secret_content {
    content_type = "BASE64"
    content      = base64encode("CHANGE_ME")
  }

  lifecycle {
    ignore_changes = [secret_content]
  }
}

resource "oci_vault_secret" "tmi_client_id" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.this.id
  key_id         = oci_kms_key.master.id
  secret_name    = "tmi-client-id"

  secret_content {
    content_type = "BASE64"
    content      = base64encode("CHANGE_ME")
  }

  lifecycle {
    ignore_changes = [secret_content]
  }
}

resource "oci_vault_secret" "tmi_client_secret" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.this.id
  key_id         = oci_kms_key.master.id
  secret_name    = "tmi-client-secret"

  secret_content {
    content_type = "BASE64"
    content      = base64encode("CHANGE_ME")
  }

  lifecycle {
    ignore_changes = [secret_content]
  }
}

resource "oci_vault_secret" "llm_api_key" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.this.id
  key_id         = oci_kms_key.master.id
  secret_name    = "llm-api-key"

  secret_content {
    content_type = "BASE64"
    content      = base64encode("CHANGE_ME")
  }

  lifecycle {
    ignore_changes = [secret_content]
  }
}

resource "oci_vault_secret" "github_token" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.this.id
  key_id         = oci_kms_key.master.id
  secret_name    = "github-token"

  secret_content {
    content_type = "BASE64"
    content      = base64encode("CHANGE_ME")
  }

  lifecycle {
    ignore_changes = [secret_content]
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add infra/vault.tf
git commit -m "feat(infra): add OCI Vault, master key, and secret shells"
```

---

### Task 8: IAM — Dynamic Group and Policies

**Files:**
- Create: `infra/iam.tf`

- [ ] **Step 1: Create `infra/iam.tf`**

```hcl
# Dynamic group matching pods in the tmi-tf namespace via OKE workload identity
resource "oci_identity_dynamic_group" "tmi_tf_workload" {
  compartment_id = var.tenancy_ocid
  name           = "${var.cluster_name}-workload"
  description    = "OKE workload identity for tmi-tf-wh pods"

  matching_rule = join("", [
    "ALL {",
    "resource.type='workloadidentity',",
    "resource.compartment.id='${var.compartment_ocid}',",
    "resource.cluster.id='${oci_containerengine_cluster.this.id}',",
    "resource.namespace='${var.k8s_namespace}'",
    "}",
  ])
}

# Policy: allow the dynamic group to use queue and read vault secrets
resource "oci_identity_policy" "tmi_tf_workload" {
  compartment_id = var.compartment_ocid
  name           = "${var.cluster_name}-workload-policy"
  description    = "Allow tmi-tf-wh pods to use queue and read vault secrets"

  statements = [
    "Allow dynamic-group ${oci_identity_dynamic_group.tmi_tf_workload.name} to use queues in compartment id ${var.compartment_ocid}",
    "Allow dynamic-group ${oci_identity_dynamic_group.tmi_tf_workload.name} to read secret-family in compartment id ${var.compartment_ocid}",
    "Allow dynamic-group ${oci_identity_dynamic_group.tmi_tf_workload.name} to use vaults in compartment id ${var.compartment_ocid}",
  ]
}
```

- [ ] **Step 2: Commit**

```bash
git add infra/iam.tf
git commit -m "feat(infra): add dynamic group and IAM policies for OKE workload identity"
```

---

### Task 9: OCIR Container Repository

**Files:**
- Create: `infra/ocir.tf`

- [ ] **Step 1: Create `infra/ocir.tf`**

```hcl
resource "oci_artifacts_container_repository" "this" {
  compartment_id = var.compartment_ocid
  display_name   = "tmi-tf-wh"
  is_public      = false
}

locals {
  # OCIR image path: <region-key>.ocir.io/<tenancy-namespace>/tmi-tf-wh:<tag>
  ocir_image = join("/", [
    "${var.region}.ocir.io",
    data.oci_identity_tenancy.this.name,
    "tmi-tf-wh:${var.app_image_tag}",
  ])
}
```

- [ ] **Step 2: Commit**

```bash
git add infra/ocir.tf
git commit -m "feat(infra): add OCIR container repository"
```

---

### Task 10: API Gateway

**Files:**
- Create: `infra/api_gateway.tf`

- [ ] **Step 1: Create `infra/api_gateway.tf`**

```hcl
resource "oci_apigateway_gateway" "this" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.cluster_name}-gateway"
  endpoint_type  = "PUBLIC"
  subnet_id      = var.subnet_id_api_gateway

  freeform_tags = {
    "app" = "tmi-tf-wh"
  }
}

resource "oci_apigateway_deployment" "this" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.cluster_name}-api"
  gateway_id     = oci_apigateway_gateway.this.id
  path_prefix    = "/"

  specification {
    routes {
      path    = "/webhook"
      methods = ["POST"]

      backend {
        type = "HTTP_BACKEND"
        url  = "http://${kubernetes_service.tmi_tf_wh.status[0].load_balancer[0].ingress[0].ip}:8080/webhook"

        connect_timeout_in_seconds = 10
        read_timeout_in_seconds    = 30
        send_timeout_in_seconds    = 10
      }
    }

    routes {
      path    = "/health"
      methods = ["GET"]

      backend {
        type = "HTTP_BACKEND"
        url  = "http://${kubernetes_service.tmi_tf_wh.status[0].load_balancer[0].ingress[0].ip}:8080/health"

        connect_timeout_in_seconds = 5
        read_timeout_in_seconds    = 10
        send_timeout_in_seconds    = 5
      }
    }
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add infra/api_gateway.tf
git commit -m "feat(infra): add public API Gateway with webhook and health routes"
```

---

### Task 11: Kubernetes Resources — Namespace, ServiceAccount, Deployment, Service

**Files:**
- Create: `infra/k8s.tf`

- [ ] **Step 1: Create `infra/k8s.tf`**

```hcl
resource "kubernetes_namespace" "tmi_tf" {
  metadata {
    name = var.k8s_namespace
  }

  depends_on = [oci_containerengine_node_pool.this]
}

# ServiceAccount with OKE workload identity annotation
resource "kubernetes_service_account" "tmi_tf_wh" {
  metadata {
    name      = "tmi-tf-wh"
    namespace = kubernetes_namespace.tmi_tf.metadata[0].name
  }
}

# Construct OCI service endpoints from region
locals {
  queue_endpoint   = "https://cell-1.queue.oc1.${var.region}.oci.oraclecloud.com"
  vault_endpoint   = "https://vaults.${var.region}.oci.oraclecloud.com"
  secrets_endpoint = "https://secrets.vaults.${var.region}.oci.oraclecloud.com"
}

resource "kubernetes_deployment" "tmi_tf_wh" {
  metadata {
    name      = "tmi-tf-wh"
    namespace = kubernetes_namespace.tmi_tf.metadata[0].name

    labels = {
      app = "tmi-tf-wh"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "tmi-tf-wh"
      }
    }

    template {
      metadata {
        labels = {
          app = "tmi-tf-wh"
        }
      }

      spec {
        service_account_name = kubernetes_service_account.tmi_tf_wh.metadata[0].name

        container {
          name  = "tmi-tf-wh"
          image = local.ocir_image

          port {
            container_port = 8080
            protocol       = "TCP"
          }

          env {
            name  = "QUEUE_OCID"
            value = oci_queue_queue.this.id
          }

          env {
            name  = "VAULT_OCID"
            value = oci_kms_vault.this.id
          }

          env {
            name  = "OCI_COMPARTMENT_ID"
            value = var.compartment_ocid
          }

          env {
            name  = "OCI_REGION"
            value = var.region
          }

          env {
            name  = "QUEUE_ENDPOINT"
            value = local.queue_endpoint
          }

          env {
            name  = "VAULT_ENDPOINT"
            value = local.vault_endpoint
          }

          env {
            name  = "SECRETS_ENDPOINT"
            value = local.secrets_endpoint
          }

          env {
            name  = "LLM_PROVIDER"
            value = var.llm_provider
          }

          env {
            name  = "TMI_SERVER_URL"
            value = var.tmi_server_url
          }

          env {
            name  = "TMI_OAUTH_IDP"
            value = "tmi"
          }

          env {
            name  = "TMI_CLIENT_PATH"
            value = "/opt/tmi-client"
          }

          env {
            name  = "SERVER_PORT"
            value = "8080"
          }

          env {
            name  = "MAX_CONCURRENT_JOBS"
            value = tostring(var.max_concurrent_jobs)
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = 8080
            }

            initial_delay_seconds = 15
            period_seconds        = 30
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = 8080
            }

            initial_delay_seconds = 10
            period_seconds        = 10
          }

          resources {
            requests = {
              cpu    = "500m"
              memory = "512Mi"
            }

            limits = {
              cpu    = "1"
              memory = "1Gi"
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "tmi_tf_wh" {
  metadata {
    name      = "tmi-tf-wh"
    namespace = kubernetes_namespace.tmi_tf.metadata[0].name

    annotations = {
      "oci.oraclecloud.com/load-balancer-type" = "lb"
    }
  }

  spec {
    type = "LoadBalancer"

    selector = {
      app = "tmi-tf-wh"
    }

    port {
      port        = 8080
      target_port = 8080
      protocol    = "TCP"
    }
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add infra/k8s.tf
git commit -m "feat(infra): add K8s deployment, service, service account, namespace"
```

---

### Task 12: Terraform Outputs

**Files:**
- Create: `infra/outputs.tf`

- [ ] **Step 1: Create `infra/outputs.tf`**

```hcl
output "cluster_id" {
  description = "OCID of the OKE cluster"
  value       = oci_containerengine_cluster.this.id
}

output "cluster_kubernetes_version" {
  description = "Kubernetes version of the OKE cluster"
  value       = local.k8s_version
}

output "queue_ocid" {
  description = "OCID of the OCI Queue"
  value       = oci_queue_queue.this.id
}

output "vault_ocid" {
  description = "OCID of the OCI Vault"
  value       = oci_kms_vault.this.id
}

output "ocir_image" {
  description = "Full OCIR image path for the tmi-tf-wh container"
  value       = local.ocir_image
}

output "api_gateway_url" {
  description = "Public URL of the API Gateway"
  value       = oci_apigateway_gateway.this.hostname
}

output "webhook_url" {
  description = "Full webhook endpoint URL"
  value       = "https://${oci_apigateway_gateway.this.hostname}/webhook"
}

output "load_balancer_ip" {
  description = "IP of the K8s LoadBalancer service"
  value       = kubernetes_service.tmi_tf_wh.status[0].load_balancer[0].ingress[0].ip
}

output "queue_endpoint" {
  description = "OCI Queue service endpoint (for in-cluster use)"
  value       = local.queue_endpoint
}

output "vault_endpoint" {
  description = "OCI Vault service endpoint (for in-cluster use)"
  value       = local.vault_endpoint
}

output "secrets_endpoint" {
  description = "OCI Secrets service endpoint (for in-cluster use)"
  value       = local.secrets_endpoint
}
```

- [ ] **Step 2: Commit**

```bash
git add infra/outputs.tf
git commit -m "feat(infra): add terraform outputs for cluster, queue, vault, gateway"
```

---

### Task 13: Validate Terraform

- [ ] **Step 1: Run `terraform fmt`**

Run: `cd infra && terraform fmt -check -recursive`
Expected: All files formatted correctly (or fix formatting)

- [ ] **Step 2: Run `terraform validate`**

Run: `cd infra && terraform init -backend=false && terraform validate`
Expected: `Success! The configuration is valid.`

Note: Full `terraform plan` requires real OCI credentials and tfvars — validation only checks syntax and internal consistency.

- [ ] **Step 3: Commit any formatting fixes**

```bash
git add infra/
git commit -m "style(infra): format terraform files"
```

---

### Task 14: Final lint + test pass on Python changes

- [ ] **Step 1: Run full quality checks**

Run: `uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -v`
Expected: All pass with no errors

- [ ] **Step 2: Fix any issues found, commit if needed**
