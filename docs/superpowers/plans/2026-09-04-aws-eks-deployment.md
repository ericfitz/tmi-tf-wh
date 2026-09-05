# AWS EKS Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy `tmi-tf-wh` into the existing TMI EKS cluster behind `https://webhook.tmi.dev/tf/webhook`, with SQS as the job queue.

**Architecture:** One pod in namespace `tmi-tf` on cluster `tmi-eks` (us-east-1). A second ALB, created through the cluster's existing AWS Load Balancer Controller via an IngressGroup named `tmi-webhooks`, serves `webhook.tmi.dev`; this app owns the `/tf` path prefix. Jobs flow through an SQS queue accessed via an IRSA role. Secrets live in a Kubernetes Secret. Terraform in `infra/aws/` owns everything AWS-side; the existing OCI Terraform moves to `infra/oci/`.

**Tech Stack:** Python 3.12, FastAPI, boto3, Terraform 1.15 (`hashicorp/aws`, `hashicorp/kubernetes`), Docker buildx, Amazon ECR/SQS/ACM/Route53, EKS 1.36.

**Spec:** `docs/superpowers/specs/2026-09-04-aws-eks-deployment-design.md`

## Global Constraints

- AWS CLI profile: `tmi`. Region for all resources: `us-east-1` (the profile's default is us-east-2; always pass region explicitly).
- Cluster: `tmi-eks`. Kube context: `tmi-eks`. Namespace: `tmi-tf`. Never touch namespace `tmi-platform`.
- Container image: `linux/amd64` (nodes are x86_64).
- Hostname: `webhook.tmi.dev`. URL prefix for this app: `/tf`. IngressGroup name: `tmi-webhooks`. HTTPS only, no port 80 listener.
- LLM: `LLM_PROVIDER=anthropic`, `LLM_MODEL=claude-fable-5-1`.
- Terraform state: S3 bucket `tmi-tfstate-967218005408`, key `tmi-tf-wh/aws/terraform.tfstate`, lock table `tmi-tf-locks`.
- Lint/type/test gates before every commit: `uv run ruff check tmi_tf/ tests/`, `uv run ruff format --check tmi_tf/ tests/`, `uv run pyright`, `uv run pytest tests/`.
- Terraform gates: `terraform fmt -check -recursive infra/` and `terraform -chdir=<dir> validate` (after `init -backend=false`).
- Commit trailer on every commit:
  ```
  Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01GMzqBtEK2dhg8FxrUPjuS8
  ```
- Do not `terraform apply` or push images as part of these tasks. Applying is a separate, user-run step documented in Task 6's README.

---

## File map

| Path | Responsibility |
|------|----------------|
| `infra/oci/*` | Existing OCI Terraform, relocated unchanged (Task 1) |
| `tmi_tf/providers/aws.py` | `AwsQueueProvider` over boto3 SQS (Task 2) |
| `tmi_tf/providers/__init__.py` | Factory gains `"aws"` branch (Task 2) |
| `tmi_tf/config.py` | `queue_url`, `aws_region`, `"aws"` inference (Task 2) |
| `tests/test_providers_aws.py` | Unit tests for the provider (Task 2) |
| `tmi_tf/server.py` | Routes on an `APIRouter` mounted under `URL_PREFIX` (Task 3) |
| `deploy/docker/Dockerfile.aws` | Header comment fix (Task 4) |
| `scripts/push-aws.sh` | Build for amd64 and push to ECR (Task 4) |
| `infra/aws/versions.tf` | Terraform/provider versions, S3 backend, providers (Task 5) |
| `infra/aws/variables.tf` | Inputs (Task 5) |
| `infra/aws/data.tf` | Lookups: cluster, OIDC provider, hosted zone (Task 5) |
| `infra/aws/ecr.tf`, `sqs.tf`, `iam.tf`, `dns.tf`, `k8s.tf`, `outputs.tf` | Resources per spec (Task 5) |
| `infra/aws/terraform.tfvars.example`, `backend.hcl.example` | Deployer templates (Task 5) |
| `infra/aws/README.md` | Apply order, TMI-side steps, multiplexing contract (Task 6) |
| `.env.example`, `deploy/docker/README.md` | Doc updates (Tasks 2, 4) |

---

### Task 1: Relocate OCI Terraform to `infra/oci/`

**Files:**
- Move: every tracked file under `infra/` → `infra/oci/`
- Move (untracked, local only): `infra/.terraform/`, `infra/terraform.tfvars` → `infra/oci/`
- Modify: `docs/superpowers/plans/2026-03-30-oke-terraform-deployment.md` (path references only)

**Interfaces:**
- Produces: `infra/oci/` as the OCI root module; `infra/aws/` is free for Task 5.

- [ ] **Step 1: Move the tracked files with git**

```bash
cd /Users/efitz/Projects/tmi-tf-wh
mkdir -p infra/oci
git mv infra/.terraform.lock.hcl infra/api_gateway.tf infra/iam.tf infra/k8s.tf infra/networking.tf infra/ocir.tf infra/oke.tf infra/outputs.tf infra/queue.tf infra/terraform.tfvars.example infra/variables.tf infra/vault.tf infra/versions.tf infra/oci/
```

- [ ] **Step 2: Move the untracked local files**

```bash
mv infra/.terraform infra/oci/.terraform
mv infra/terraform.tfvars infra/oci/terraform.tfvars
git check-ignore -q infra/oci/terraform.tfvars infra/oci/.terraform && echo "still ignored"
```

Expected: `still ignored`. If it prints nothing, stop and report; `.gitignore` has `*.tfvars` and `**/.terraform/` so this should pass.

- [ ] **Step 3: Update the historical plan's path table**

In `docs/superpowers/plans/2026-03-30-oke-terraform-deployment.md`, replace every `infra/` with `infra/oci/` (lines 15-27). Use `sed -i.bak 's#`infra/#`infra/oci/#g' <file>` then diff, then delete the `.bak`.

- [ ] **Step 4: Validate the OCI module still initializes**

```bash
terraform -chdir=infra/oci init -backend=false -input=false >/dev/null && terraform -chdir=infra/oci validate
terraform fmt -check -recursive infra/
```

Expected: `Success! The configuration is valid.` and no fmt output.

- [ ] **Step 5: Commit**

```bash
git add infra docs/superpowers/plans/2026-03-30-oke-terraform-deployment.md
git status --short   # confirm only renames + the doc; no tfvars, no .terraform
git commit -m "chore(infra): move OCI terraform to infra/oci/"
```

---

### Task 2: `AwsQueueProvider` (SQS) with config inference

**Files:**
- Create: `tmi_tf/providers/aws.py`
- Create: `tests/test_providers_aws.py`
- Modify: `tmi_tf/providers/__init__.py` (`get_queue_provider`, lines ~115-135)
- Modify: `tmi_tf/config.py` (queue section, lines ~100-125)
- Modify: `tests/conftest.py` (`_LEAKY_ENV_VARS`)
- Modify: `tests/test_providers.py::TestGetQueueProvider::test_factory_raises_for_unknown_provider` (uses `"aws"` as the unknown name; change to `"bogus"`)
- Modify: `pyproject.toml` (add `boto3`)
- Modify: `.env.example` (server-mode section)

**Interfaces:**
- Consumes: `tmi_tf.providers.QueueMessage(body: dict, receipt: str)`; `QueueProvider` protocol (`publish(message: dict) -> None`, `consume(max_messages: int = 1, visibility_timeout: int = 900) -> list[QueueMessage]`, `delete(receipt: str) -> None`).
- Produces: `AwsQueueProvider(queue_url: str, region: str | None = None)`; `Config.queue_url: str | None`; `Config.aws_region: str | None`; `Config.queue_provider == "aws"` when `QUEUE_URL` is set. Env vars `QUEUE_URL`, `AWS_REGION`, `QUEUE_PROVIDER=aws` used by Task 5's Deployment.

- [ ] **Step 1: Add boto3 and lock**

In `pyproject.toml` `dependencies`, after `"oci>=2.168.2",` add:

```toml
    "boto3>=1.34.0",
```

Run: `uv sync`
Expected: lock updates, boto3 installed.

- [ ] **Step 2: Write the failing provider tests**

Create `tests/test_providers_aws.py`:

```python
"""Tests for the AWS SQS queue provider."""

import json
from unittest.mock import MagicMock, patch

from tmi_tf.providers.aws import AwsQueueProvider

QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/123456789012/tmi-tf-wh-jobs"


class TestAwsQueueProvider:
    @patch("tmi_tf.providers.aws.AwsQueueProvider._get_client")
    def test_publish_sends_json_body(self, mock_get: MagicMock) -> None:
        client = MagicMock()
        mock_get.return_value = client
        provider = AwsQueueProvider(queue_url=QUEUE_URL)
        provider.publish({"job_id": "j1", "threat_model_id": "tm-1"})
        client.send_message.assert_called_once_with(
            QueueUrl=QUEUE_URL,
            MessageBody=json.dumps({"job_id": "j1", "threat_model_id": "tm-1"}),
        )

    @patch("tmi_tf.providers.aws.AwsQueueProvider._get_client")
    def test_consume_returns_messages(self, mock_get: MagicMock) -> None:
        client = MagicMock()
        client.receive_message.return_value = {
            "Messages": [{"Body": json.dumps({"job_id": "j1"}), "ReceiptHandle": "r-1"}]
        }
        mock_get.return_value = client
        provider = AwsQueueProvider(queue_url=QUEUE_URL)
        messages = provider.consume(max_messages=2, visibility_timeout=600)
        assert len(messages) == 1
        assert messages[0].body == {"job_id": "j1"}
        assert messages[0].receipt == "r-1"
        client.receive_message.assert_called_once_with(
            QueueUrl=QUEUE_URL,
            MaxNumberOfMessages=2,
            VisibilityTimeout=600,
            WaitTimeSeconds=5,
        )

    @patch("tmi_tf.providers.aws.AwsQueueProvider._get_client")
    def test_consume_caps_batch_at_sqs_limit(self, mock_get: MagicMock) -> None:
        client = MagicMock()
        client.receive_message.return_value = {}
        mock_get.return_value = client
        AwsQueueProvider(queue_url=QUEUE_URL).consume(max_messages=25)
        assert client.receive_message.call_args.kwargs["MaxNumberOfMessages"] == 10

    @patch("tmi_tf.providers.aws.AwsQueueProvider._get_client")
    def test_consume_empty_when_no_messages_key(self, mock_get: MagicMock) -> None:
        client = MagicMock()
        client.receive_message.return_value = {}
        mock_get.return_value = client
        assert AwsQueueProvider(queue_url=QUEUE_URL).consume() == []

    @patch("tmi_tf.providers.aws.AwsQueueProvider._get_client")
    def test_consume_deletes_unparseable_messages(self, mock_get: MagicMock) -> None:
        client = MagicMock()
        client.receive_message.return_value = {
            "Messages": [
                {"Body": "not-json", "ReceiptHandle": "bad"},
                {"Body": json.dumps({"job_id": "j2"}), "ReceiptHandle": "good"},
            ]
        }
        mock_get.return_value = client
        messages = AwsQueueProvider(queue_url=QUEUE_URL).consume()
        assert [m.receipt for m in messages] == ["good"]
        client.delete_message.assert_called_once_with(
            QueueUrl=QUEUE_URL, ReceiptHandle="bad"
        )

    @patch("tmi_tf.providers.aws.AwsQueueProvider._get_client")
    def test_delete(self, mock_get: MagicMock) -> None:
        client = MagicMock()
        mock_get.return_value = client
        AwsQueueProvider(queue_url=QUEUE_URL).delete("r-1")
        client.delete_message.assert_called_once_with(
            QueueUrl=QUEUE_URL, ReceiptHandle="r-1"
        )

    @patch("boto3.client")
    def test_get_client_passes_region_and_caches(self, mock_boto: MagicMock) -> None:
        provider = AwsQueueProvider(queue_url=QUEUE_URL, region="us-east-1")
        first = provider._get_client()
        second = provider._get_client()
        assert first is second
        mock_boto.assert_called_once_with("sqs", region_name="us-east-1")
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_providers_aws.py -v`
Expected: collection error, `ModuleNotFoundError: No module named 'tmi_tf.providers.aws'`.

- [ ] **Step 4: Implement the provider**

Create `tmi_tf/providers/aws.py`:

```python
"""AWS provider: SQS queue.

Credentials come from the default boto3 chain. In EKS the ServiceAccount's
IRSA annotation injects AWS_ROLE_ARN / AWS_WEB_IDENTITY_TOKEN_FILE, so no
explicit configuration is needed inside the pod.
"""

import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tmi_tf.providers import QueueMessage

logger = logging.getLogger(__name__)

# SQS rejects MaxNumberOfMessages > 10.
_SQS_MAX_BATCH = 10
# Long-poll briefly so an idle worker does not spin on empty receives.
# Runs inside asyncio.to_thread, so it never blocks the event loop.
_WAIT_SECONDS = 5


class AwsQueueProvider:
    """SQS wrapper for publish/consume/delete operations."""

    def __init__(self, queue_url: str, region: str | None = None) -> None:
        self._queue_url = queue_url
        self._region = region
        self._client = None

    def _get_client(self):  # type: ignore[return]
        """Lazy-initialize and return the boto3 SQS client."""
        if self._client is None:
            import boto3  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

            self._client = boto3.client("sqs", region_name=self._region)
        return self._client

    def publish(self, message: dict[str, Any]) -> None:
        """Serialize message to JSON and send it to the queue."""
        self._get_client().send_message(
            QueueUrl=self._queue_url, MessageBody=json.dumps(message)
        )
        logger.info(
            "Published message for job_id=%s to %s",
            message.get("job_id", "<unknown>"),
            self._queue_url,
        )

    def consume(
        self, max_messages: int = 1, visibility_timeout: int = 900
    ) -> list["QueueMessage"]:
        """Receive messages and return parsed QueueMessage objects.

        Messages whose body is not valid JSON are deleted and skipped.
        """
        from tmi_tf.providers import QueueMessage

        response = self._get_client().receive_message(
            QueueUrl=self._queue_url,
            MaxNumberOfMessages=min(max_messages, _SQS_MAX_BATCH),
            VisibilityTimeout=visibility_timeout,
            WaitTimeSeconds=_WAIT_SECONDS,
        )
        result: list[QueueMessage] = []
        for msg in response.get("Messages", []):
            receipt = msg["ReceiptHandle"]
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, TypeError) as e:
                logger.warning(
                    "Failed to parse message body (receipt=%s): %s — deleting",
                    receipt,
                    e,
                )
                try:
                    self.delete(receipt)
                except Exception as del_err:
                    logger.error(
                        "Failed to delete unparseable message (receipt=%s): %s",
                        receipt,
                        del_err,
                    )
                continue
            result.append(QueueMessage(body=body, receipt=receipt))
        return result

    def delete(self, receipt: str) -> None:
        """Delete a message from the queue by its receipt handle."""
        self._get_client().delete_message(
            QueueUrl=self._queue_url, ReceiptHandle=receipt
        )
        logger.debug("Deleted message receipt=%s from %s", receipt, self._queue_url)
```

- [ ] **Step 5: Run the provider tests**

Run: `uv run pytest tests/test_providers_aws.py -v`
Expected: 7 passed.

- [ ] **Step 6: Write the failing config and factory tests**

Append to `tests/test_providers.py` (inside `TestGetQueueProvider`):

```python
    def test_factory_returns_aws_provider(self):
        config = MagicMock()
        config.queue_provider = "aws"
        config.queue_url = "https://sqs.us-east-1.amazonaws.com/1/q"
        config.aws_region = "us-east-1"
        provider = get_queue_provider(config)
        from tmi_tf.providers.aws import AwsQueueProvider

        assert isinstance(provider, AwsQueueProvider)
        assert provider._queue_url == "https://sqs.us-east-1.amazonaws.com/1/q"
        assert provider._region == "us-east-1"
```

And in the same class change `test_factory_raises_for_unknown_provider` so it sets `config.queue_provider = "bogus"` instead of `"aws"`.

Append a new class at the end of `tests/test_providers.py`:

```python
class TestQueueProviderConfig:
    @patch("tmi_tf.config.load_dotenv")
    def test_infers_aws_when_queue_url_set(self, mock_dotenv):
        with patch.dict(
            os.environ,
            {
                "QUEUE_URL": "https://sqs.us-east-1.amazonaws.com/1/q",
                "AWS_REGION": "us-east-1",
                "ANTHROPIC_API_KEY": "test-key",
            },
            clear=True,
        ):
            from tmi_tf.config import Config

            config = Config()
            assert config.queue_provider == "aws"
            assert config.queue_url == "https://sqs.us-east-1.amazonaws.com/1/q"
            assert config.aws_region == "us-east-1"

    @patch("tmi_tf.config.load_dotenv")
    def test_oci_wins_when_both_ocid_and_url_set(self, mock_dotenv):
        with patch.dict(
            os.environ,
            {
                "QUEUE_OCID": "ocid1.queue.oc1..test",
                "QUEUE_URL": "https://sqs.us-east-1.amazonaws.com/1/q",
                "ANTHROPIC_API_KEY": "test-key",
            },
            clear=True,
        ):
            from tmi_tf.config import Config

            assert Config().queue_provider == "oci"

    @patch("tmi_tf.config.load_dotenv")
    def test_explicit_provider_overrides_inference(self, mock_dotenv):
        with patch.dict(
            os.environ,
            {
                "QUEUE_PROVIDER": "memory",
                "QUEUE_URL": "https://sqs.us-east-1.amazonaws.com/1/q",
                "ANTHROPIC_API_KEY": "test-key",
            },
            clear=True,
        ):
            from tmi_tf.config import Config

            assert Config().queue_provider == "memory"
```

- [ ] **Step 7: Run to verify they fail**

Run: `uv run pytest tests/test_providers.py -k "aws or QueueProviderConfig" -v`
Expected: `test_factory_returns_aws_provider` fails with `ValueError: Unknown queue provider: 'aws'`; the config tests fail on `queue_provider == "aws"` / missing `queue_url` attribute.

- [ ] **Step 8: Implement config and factory changes**

In `tmi_tf/config.py`, replace the queue block:

```python
        self.queue_ocid: str | None = os.getenv("QUEUE_OCID") or None
        self.vault_ocid: str | None = os.getenv("VAULT_OCID") or None
        self.queue_url: str | None = os.getenv("QUEUE_URL") or None
        self.aws_region: str | None = os.getenv("AWS_REGION") or None
```

and the inference:

```python
        # Queue provider selection (inferred from QUEUE_OCID / QUEUE_URL if not explicit)
        explicit_queue_provider = os.getenv("QUEUE_PROVIDER")
        if explicit_queue_provider:
            self.queue_provider: str = explicit_queue_provider
        elif self.queue_ocid:
            self.queue_provider = "oci"
        elif self.queue_url:
            self.queue_provider = "aws"
        else:
            self.queue_provider = "none"
```

In `tmi_tf/providers/__init__.py`, `get_queue_provider`, add before the `memory` branch:

```python
    elif config.queue_provider == "aws":
        from tmi_tf.providers.aws import AwsQueueProvider

        return AwsQueueProvider(
            queue_url=config.queue_url or "", region=config.aws_region
        )
```

and change the error text to `"Must be 'oci', 'aws', or 'memory'."`.

In `tests/conftest.py`, add `"QUEUE_URL",` and `"AWS_REGION",` to `_LEAKY_ENV_VARS`.

- [ ] **Step 9: Run the full suite and gates**

```bash
uv run pytest tests/ -q
uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright
```

Expected: all pass. If pyright complains about `boto3` imports, the inline `# pyright: ignore[reportMissingImports]` matches the existing oci pattern; do not add stubs packages.

- [ ] **Step 10: Document in `.env.example`**

Replace the two queue comment lines in the server-mode section with:

```
# Queue provider: "oci" (inferred from QUEUE_OCID), "aws" (inferred from QUEUE_URL),
# or "memory" (local dev, in-process)
# QUEUE_PROVIDER=memory
# QUEUE_OCID=ocid1.queue.oc1..example
# QUEUE_URL=https://sqs.us-east-1.amazonaws.com/123456789012/tmi-tf-wh-jobs
# AWS_REGION=us-east-1
```

- [ ] **Step 11: Commit**

```bash
git add pyproject.toml uv.lock tmi_tf/providers/aws.py tmi_tf/providers/__init__.py tmi_tf/config.py tests/test_providers_aws.py tests/test_providers.py tests/conftest.py .env.example
git commit -m "feat(providers): add AWS SQS queue provider"
```

---

### Task 3: Serve routes under `URL_PREFIX`

**Files:**
- Modify: `tmi_tf/server.py` (route decorators at lines 88, 184, 196; add `include_router` at end)
- Modify: `tests/test_server.py` (new test class)
- Modify: `.env.example` (server-mode section)

**Interfaces:**
- Produces: env var `URL_PREFIX` (default empty; must start with `/`, no trailing slash) under which `/webhook`, `/health`, `/status` are served. Task 5's Deployment sets `URL_PREFIX=/tf` and probes `/tf/health`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_server.py`:

```python
class TestUrlPrefix:
    def test_routes_served_under_prefix(self, monkeypatch):
        import importlib

        monkeypatch.setenv("URL_PREFIX", "/tf")
        importlib.reload(server_module)
        try:
            c = TestClient(server_module.app, raise_server_exceptions=False)
            assert c.get("/tf/health").status_code == 200
            assert c.get("/health").status_code == 404
        finally:
            monkeypatch.delenv("URL_PREFIX")
            importlib.reload(server_module)

    def test_no_prefix_by_default(self, client):
        assert client.get("/health").status_code == 200
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_server.py::TestUrlPrefix -v`
Expected: `test_routes_served_under_prefix` fails (`/tf/health` returns 404).

- [ ] **Step 3: Implement**

In `tmi_tf/server.py`:

1. Add `import os` to the imports and change the FastAPI import to `from fastapi import APIRouter, FastAPI, Request  # ty:ignore[unresolved-import]`.
2. Directly after `app = FastAPI(lifespan=lifespan)` add:

```python
router = APIRouter()
```

3. Change the three decorators `@app.post("/webhook")`, `@app.get("/health")`, `@app.get("/status")` to `@router.post(...)` / `@router.get(...)`.
4. At the very end of the file add:

```python
# Mount under an optional prefix so several webhook apps can share one
# hostname behind a path-routing load balancer (e.g. ALB IngressGroup).
# Must start with "/" when set, e.g. URL_PREFIX=/tf. Read from the
# environment at import time because routes are registered at import time.
app.include_router(router, prefix=os.environ.get("URL_PREFIX", "").rstrip("/"))
```

- [ ] **Step 4: Run the server tests and gates**

```bash
uv run pytest tests/test_server.py -v
uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright
```

Expected: all pass, including the pre-existing webhook/health/status tests.

- [ ] **Step 5: Document**

In `.env.example` server-mode section, after `# SERVER_PORT=8080` add:

```
# Path prefix when several webhook apps share one hostname (e.g. /tf). Empty = none.
# URL_PREFIX=
```

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/server.py tests/test_server.py .env.example
git commit -m "feat(server): mount routes under optional URL_PREFIX"
```

---

### Task 4: amd64 image build and ECR push script

**Files:**
- Modify: `deploy/docker/Dockerfile.aws:1-2`
- Create: `scripts/push-aws.sh`
- Modify: `deploy/docker/README.md`

**Interfaces:**
- Produces: image `<account>.dkr.ecr.us-east-1.amazonaws.com/tmi-tf-wh:<tag>` (plus `:v<version>` when tag is `latest`). Task 5's Deployment references `${repository_url}:${var.app_image_tag}`.

- [ ] **Step 1: Fix the Dockerfile header**

Change the first two lines of `deploy/docker/Dockerfile.aws` to:

```dockerfile
# AWS build — Amazon Linux 2023 from AWS Public ECR
# Build: docker buildx build --platform linux/amd64 -f deploy/docker/Dockerfile.aws -t <tag> .
```

- [ ] **Step 2: Write the push script**

Create `scripts/push-aws.sh` (then `chmod +x`):

```bash
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
```

- [ ] **Step 3: Check the script parses and its help works**

```bash
chmod +x scripts/push-aws.sh
bash -n scripts/push-aws.sh && ./scripts/push-aws.sh --help
command -v shellcheck >/dev/null && shellcheck scripts/push-aws.sh || echo "shellcheck not installed; skipped"
```

Expected: help text printed, no syntax errors. Do not run a real build/push here.

- [ ] **Step 4: Update the Docker README**

In `deploy/docker/README.md`, change the AWS row's Target column to `EKS (see infra/aws/)` and replace the line `The OCI push workflow is wrapped by ...` with:

```markdown
Push workflows: [scripts/push-oci.sh](../../scripts/push-oci.sh) (OCIR, arm64) and
[scripts/push-aws.sh](../../scripts/push-aws.sh) (ECR, amd64 — the EKS nodes are x86_64).
```

- [ ] **Step 5: Commit**

```bash
git add deploy/docker/Dockerfile.aws deploy/docker/README.md scripts/push-aws.sh
git commit -m "build: add ECR push script and fix Dockerfile.aws platform note"
```

---

### Task 5: Terraform for AWS (`infra/aws/`)

**Files:**
- Create: `infra/aws/versions.tf`, `variables.tf`, `data.tf`, `ecr.tf`, `sqs.tf`, `iam.tf`, `dns.tf`, `k8s.tf`, `outputs.tf`, `terraform.tfvars.example`, `backend.hcl.example`
- Verify: `.gitignore` already ignores `*.tfvars` and `**/.terraform/`; add `backend.hcl` (Step 1).

**Interfaces:**
- Consumes: env contract from Tasks 2-3 (`QUEUE_PROVIDER`, `QUEUE_URL`, `AWS_REGION`, `URL_PREFIX`), image from Task 4, `VAULT_SECRET_MAP` env names (`WEBHOOK_SECRET`, `TMI_CLIENT_ID`, `TMI_CLIENT_SECRET`, `LLM_API_KEY`, `GITHUB_TOKEN`).
- Produces: outputs `webhook_url`, `queue_url`, `ecr_repository_url`, `pod_role_arn`, `alb_hostname`.

- [ ] **Step 1: Ignore local backend config**

Append to `.gitignore`:

```
infra/aws/backend.hcl
```

- [ ] **Step 2: `versions.tf`**

```hcl
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.25.0"
    }
  }

  # Bucket / region / lock table come from `terraform init -backend-config=backend.hcl`
  # (see backend.hcl.example). Key and encryption are pinned here.
  backend "s3" {
    key     = "tmi-tf-wh/aws/terraform.tfstate"
    encrypt = true
  }
}

provider "aws" {
  region  = var.region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project   = "tmi-tf-wh"
      ManagedBy = "terraform"
    }
  }
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks", "get-token",
      "--cluster-name", var.cluster_name,
      "--region", var.region,
      "--profile", var.aws_profile,
    ]
  }
}
```

- [ ] **Step 3: `variables.tf`**

```hcl
# --- Where to deploy ---

variable "region" {
  description = "AWS region holding the EKS cluster"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile used by the aws provider and `aws eks get-token`"
  type        = string
  default     = "tmi"
}

variable "cluster_name" {
  description = "Name of the existing EKS cluster"
  type        = string
  default     = "tmi-eks"
}

variable "hosted_zone_name" {
  description = "Route53 hosted zone that owns the webhook hostname"
  type        = string
  default     = "tmi.dev"
}

variable "hostname" {
  description = "Public hostname shared by all TMI webhook apps"
  type        = string
  default     = "webhook.tmi.dev"
}

variable "ingress_group" {
  description = "ALB IngressGroup name; every webhook app's Ingress joins this group"
  type        = string
  default     = "tmi-webhooks"
}

variable "url_prefix" {
  description = "Path prefix this app owns on the shared hostname (must start with /)"
  type        = string
  default     = "/tf"

  validation {
    condition     = startswith(var.url_prefix, "/") && !endswith(var.url_prefix, "/")
    error_message = "url_prefix must start with '/' and not end with '/'."
  }
}

# --- App ---

variable "app_name" {
  description = "Name used for the namespace, workloads, queue, role and ECR repo"
  type        = string
  default     = "tmi-tf-wh"
}

variable "k8s_namespace" {
  description = "Kubernetes namespace for the deployment"
  type        = string
  default     = "tmi-tf"
}

variable "app_image_tag" {
  description = "Container image tag pushed by scripts/push-aws.sh"
  type        = string
  default     = "latest"
}

variable "llm_provider" {
  description = "LLM provider (anthropic, openai, xai, gemini)"
  type        = string
  default     = "anthropic"
}

variable "llm_model" {
  description = "Model override passed as LLM_MODEL"
  type        = string
  default     = "claude-fable-5-1"
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

# --- Secrets (put in an untracked secrets.auto.tfvars) ---

variable "webhook_secret" {
  description = "HMAC shared secret configured on the TMI webhook subscription"
  type        = string
  sensitive   = true
}

variable "tmi_client_id" {
  description = "TMI client_credentials OAuth client id"
  type        = string
  sensitive   = true
}

variable "tmi_client_secret" {
  description = "TMI client_credentials OAuth client secret"
  type        = string
  sensitive   = true
}

variable "llm_api_key" {
  description = "API key for llm_provider (mapped to the provider's env var by the app)"
  type        = string
  sensitive   = true
}

variable "github_token" {
  description = "GitHub token for cloning repositories (may be empty)"
  type        = string
  sensitive   = true
  default     = ""
}
```

- [ ] **Step 4: `data.tf`**

```hcl
data "aws_caller_identity" "current" {}

data "aws_eks_cluster" "this" {
  name = var.cluster_name
}

data "aws_iam_openid_connect_provider" "eks" {
  url = data.aws_eks_cluster.this.identity[0].oidc[0].issuer
}

data "aws_route53_zone" "this" {
  name = "${var.hosted_zone_name}."
}

locals {
  oidc_provider_url = replace(data.aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")
  service_account   = var.app_name
  image             = "${aws_ecr_repository.this.repository_url}:${var.app_image_tag}"
}
```

- [ ] **Step 5: `ecr.tf`**

```hcl
resource "aws_ecr_repository" "this" {
  name                 = var.app_name
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "this" {
  repository = aws_ecr_repository.this.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the 10 most recent images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}
```

- [ ] **Step 6: `sqs.tf`**

```hcl
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.app_name}-jobs-dlq"
  message_retention_seconds = 1209600 # 14 days
}

resource "aws_sqs_queue" "jobs" {
  name                       = "${var.app_name}-jobs"
  visibility_timeout_seconds = 900
  message_retention_seconds  = 86400 # 24 h, matches MAX_MESSAGE_AGE_HOURS
  receive_wait_time_seconds  = 5

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 3
  })
}
```

- [ ] **Step 7: `iam.tf`**

```hcl
# IRSA: the pod's ServiceAccount assumes this role via the cluster OIDC provider.
resource "aws_iam_role" "pod" {
  name = "${var.app_name}-pod"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.eks.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.oidc_provider_url}:aud" = "sts.amazonaws.com"
          "${local.oidc_provider_url}:sub" = "system:serviceaccount:${var.k8s_namespace}:${local.service_account}"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "sqs" {
  name = "sqs-jobs"
  role = aws_iam_role.pod.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sqs:SendMessage",
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
      ]
      Resource = aws_sqs_queue.jobs.arn
    }]
  })
}
```

- [ ] **Step 8: `dns.tf`**

```hcl
# Certificate + DNS for the shared webhook hostname. This repo creates them as
# the first tenant; move them to a shared stack when a second webhook app exists.

resource "aws_acm_certificate" "webhook" {
  domain_name       = var.hostname
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "validation" {
  for_each = {
    for dvo in aws_acm_certificate.webhook.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id         = data.aws_route53_zone.this.zone_id
  name            = each.value.name
  type            = each.value.type
  ttl             = 60
  records         = [each.value.record]
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "webhook" {
  certificate_arn         = aws_acm_certificate.webhook.arn
  validation_record_fqdns = [for r in aws_route53_record.validation : r.fqdn]
}

resource "aws_route53_record" "webhook" {
  zone_id = data.aws_route53_zone.this.zone_id
  name    = var.hostname
  type    = "CNAME"
  ttl     = 300
  records = [kubernetes_ingress_v1.this.status[0].load_balancer[0].ingress[0].hostname]
}
```

- [ ] **Step 9: `k8s.tf`**

```hcl
resource "kubernetes_namespace_v1" "this" {
  metadata {
    name = var.k8s_namespace
    labels = {
      app        = var.app_name
      managed_by = "terraform"
    }
  }
}

resource "kubernetes_service_account_v1" "this" {
  metadata {
    name      = local.service_account
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.pod.arn
    }
  }
}

# Same approach as tmi-server on this cluster: secrets are a Kubernetes Secret
# injected via envFrom. SECRET_PROVIDER=none tells the app not to fetch any.
resource "kubernetes_secret_v1" "this" {
  metadata {
    name      = "${var.app_name}-secrets"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
  }

  data = {
    WEBHOOK_SECRET    = var.webhook_secret
    TMI_CLIENT_ID     = var.tmi_client_id
    TMI_CLIENT_SECRET = var.tmi_client_secret
    LLM_API_KEY       = var.llm_api_key
    GITHUB_TOKEN      = var.github_token
  }
}

resource "kubernetes_deployment_v1" "this" {
  metadata {
    name      = var.app_name
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    labels    = { app = var.app_name }
  }

  spec {
    replicas = 1

    selector {
      match_labels = { app = var.app_name }
    }

    template {
      metadata {
        labels = { app = var.app_name }
      }

      spec {
        service_account_name = kubernetes_service_account_v1.this.metadata[0].name

        container {
          name  = var.app_name
          image = local.image

          port {
            container_port = 8080
            protocol       = "TCP"
          }

          env_from {
            secret_ref {
              name = kubernetes_secret_v1.this.metadata[0].name
            }
          }

          env {
            name  = "QUEUE_PROVIDER"
            value = "aws"
          }
          env {
            name  = "QUEUE_URL"
            value = aws_sqs_queue.jobs.url
          }
          env {
            name  = "AWS_REGION"
            value = var.region
          }
          env {
            name  = "SECRET_PROVIDER"
            value = "none"
          }
          env {
            name  = "URL_PREFIX"
            value = var.url_prefix
          }
          env {
            name  = "LLM_PROVIDER"
            value = var.llm_provider
          }
          env {
            name  = "LLM_MODEL"
            value = var.llm_model
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
              path = "${var.url_prefix}/health"
              port = 8080
            }
            initial_delay_seconds = 15
            period_seconds        = 30
          }

          readiness_probe {
            http_get {
              path = "${var.url_prefix}/health"
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

resource "kubernetes_service_v1" "this" {
  metadata {
    name      = var.app_name
    namespace = kubernetes_namespace_v1.this.metadata[0].name
  }

  spec {
    type     = "ClusterIP"
    selector = { app = var.app_name }

    port {
      port        = 8080
      target_port = 8080
      protocol    = "TCP"
    }
  }
}

# Joins the shared ALB (IngressGroup). Other webhook apps add their own Ingress
# with the same group.name and a different path prefix; the ALB routes by path.
resource "kubernetes_ingress_v1" "this" {
  wait_for_load_balancer = true

  metadata {
    name      = var.app_name
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    annotations = {
      "alb.ingress.kubernetes.io/group.name"       = var.ingress_group
      "alb.ingress.kubernetes.io/scheme"           = "internet-facing"
      "alb.ingress.kubernetes.io/target-type"      = "ip"
      "alb.ingress.kubernetes.io/listen-ports"     = jsonencode([{ HTTPS = 443 }])
      "alb.ingress.kubernetes.io/certificate-arn"  = aws_acm_certificate_validation.webhook.certificate_arn
      "alb.ingress.kubernetes.io/healthcheck-path" = "${var.url_prefix}/health"
    }
  }

  spec {
    ingress_class_name = "alb"

    rule {
      http {
        path {
          path      = var.url_prefix
          path_type = "Prefix"

          backend {
            service {
              name = kubernetes_service_v1.this.metadata[0].name
              port {
                number = 8080
              }
            }
          }
        }
      }
    }
  }

  depends_on = [kubernetes_deployment_v1.this]
}
```

- [ ] **Step 10: `outputs.tf`**

```hcl
output "webhook_url" {
  description = "URL to register as the TMI webhook subscription target"
  value       = "https://${var.hostname}${var.url_prefix}/webhook"
}

output "alb_hostname" {
  description = "Hostname of the shared webhook ALB"
  value       = kubernetes_ingress_v1.this.status[0].load_balancer[0].ingress[0].hostname
}

output "queue_url" {
  description = "SQS jobs queue URL"
  value       = aws_sqs_queue.jobs.url
}

output "ecr_repository_url" {
  description = "ECR repository the push script targets"
  value       = aws_ecr_repository.this.repository_url
}

output "pod_role_arn" {
  description = "IRSA role assumed by the pod"
  value       = aws_iam_role.pod.arn
}
```

- [ ] **Step 11: Deployer templates**

`infra/aws/backend.hcl.example`:

```hcl
bucket         = "tmi-tfstate-967218005408"
region         = "us-east-1"
dynamodb_table = "tmi-tf-locks"
profile        = "tmi"
```

`infra/aws/terraform.tfvars.example`:

```hcl
# All values have defaults; uncomment to override.
# region              = "us-east-1"
# aws_profile         = "tmi"
# cluster_name        = "tmi-eks"
# hosted_zone_name    = "tmi.dev"
# hostname            = "webhook.tmi.dev"
# ingress_group       = "tmi-webhooks"
# url_prefix          = "/tf"
# app_image_tag       = "latest"
# llm_provider        = "anthropic"
# llm_model           = "claude-fable-5-1"
# tmi_server_url      = "https://api.tmi.dev"
# max_concurrent_jobs = 3

# Secrets go in secrets.auto.tfvars (git-ignored via *.tfvars):
# webhook_secret    = "..."
# tmi_client_id     = "..."
# tmi_client_secret = "..."
# llm_api_key       = "..."
# github_token      = ""
```

- [ ] **Step 12: Format and validate**

```bash
terraform fmt -recursive infra/aws
terraform -chdir=infra/aws init -backend=false -input=false
terraform -chdir=infra/aws validate
terraform fmt -check -recursive infra/
```

Expected: `Success! The configuration is valid.` Fix any attribute-name errors the provider reports (the kubernetes provider is strict about block names) before moving on.

- [ ] **Step 13: Commit**

```bash
git add .gitignore infra/aws
git status --short   # confirm no backend.hcl, no *.tfvars, no .terraform
git commit -m "feat(infra): terraform for AWS EKS deployment behind webhook.tmi.dev"
```

---

### Task 6: Deployment README

**Files:**
- Create: `infra/aws/README.md`

**Interfaces:**
- Consumes: outputs and variables from Task 5, script from Task 4.

- [ ] **Step 1: Write the README**

```markdown
# AWS deployment (EKS)

Deploys `tmi-tf-wh` into the existing TMI EKS cluster and exposes it at
`https://webhook.tmi.dev/tf/webhook`. Design: `docs/superpowers/specs/2026-09-04-aws-eks-deployment-design.md`.

## Prerequisites

- AWS CLI with profile `tmi`; Terraform >= 1.5; Docker with buildx; kubectl.
- The TMI cluster `tmi-eks` (us-east-1) with the AWS Load Balancer Controller
  installed, and the `tmi.dev` hosted zone in the same account.

## First deploy

```bash
cd infra/aws
cp backend.hcl.example backend.hcl
cat > secrets.auto.tfvars <<'EOF'
webhook_secret    = "<random 32+ char string>"
tmi_client_id     = "<from TMI, see below>"
tmi_client_secret = "<from TMI, see below>"
llm_api_key       = "<Anthropic API key>"
github_token      = ""
EOF

terraform init -backend-config=backend.hcl
terraform apply -target=aws_ecr_repository.this   # repo must exist before the push
../../scripts/push-aws.sh                          # builds linux/amd64, pushes :latest
terraform apply                                    # everything else
terraform output webhook_url
```

The first full apply takes a few minutes: ACM validates the certificate via
DNS, then the controller provisions the ALB, then the CNAME is written.

Verify:

```bash
curl -s https://webhook.tmi.dev/tf/health
kubectl --context tmi-eks -n tmi-tf get pods,ingress
```

## TMI-side wiring (manual, once)

1. In TMI, create an OAuth client with the `client_credentials` grant for this
   service. Put its id/secret in `secrets.auto.tfvars` and re-apply.
2. Create a webhook subscription whose target is the `webhook_url` output and
   whose shared secret equals `webhook_secret`. TMI sends a challenge; the app
   answers it automatically.

## Redeploying a new image

```bash
../../scripts/push-aws.sh --tag <git-sha>
terraform apply -var app_image_tag=<git-sha>
```

Pushing `:latest` and re-applying does not restart the pod (the spec is
unchanged); use a unique tag, or
`kubectl --context tmi-eks -n tmi-tf rollout restart deploy/tmi-tf-wh`.

## Adding another webhook app to `webhook.tmi.dev`

The hostname is served by one ALB shared through the IngressGroup
`tmi-webhooks`. To add an app:

1. Give it a unique path prefix (this app owns `/tf`) and have it serve its
   routes under that prefix.
2. Create an Ingress in the app's own namespace with
   `alb.ingress.kubernetes.io/group.name: tmi-webhooks`, `ingressClassName: alb`,
   `target-type: ip`, `listen-ports: [{"HTTPS":443}]`, the same
   `certificate-arn`, a `healthcheck-path` under its prefix, and a
   `pathType: Prefix` rule for its prefix.
3. Nothing in this repo changes. The certificate and the Route53 CNAME are
   currently owned by this stack (`dns.tf`); when a second app exists, move
   them to a shared stack with `terraform state mv` / `import`.

## Tear down

```bash
terraform destroy
```

Destroying removes the ALB only if no other Ingress remains in the group.
```

- [ ] **Step 2: Commit**

```bash
git add infra/aws/README.md
git commit -m "docs(infra): AWS deployment README"
```

---

### Task 7: Final gates and handoff

- [ ] **Step 1: Run every gate from Global Constraints**

```bash
uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q
terraform fmt -check -recursive infra/ && terraform -chdir=infra/aws validate && terraform -chdir=infra/oci validate
```

Expected: all green.

- [ ] **Step 2: Update `HANDOFF.md`** (untracked) with: branch, last commit, "not yet applied to AWS", and the apply sequence from the README. Do not commit it.

- [ ] **Step 3: Update `PROGRESS.md`** only after the branch is pushed, per the user's global rules.
