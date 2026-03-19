# TMI Terraform Analysis — Webhook Service Design

Convert the tmi-tf CLI tool into a cloud-hosted webhook service on OCI that accepts TMI webhooks to trigger Terraform infrastructure analysis.

## Architecture

### Compute

- **OCI Compute Instance**: VM.Standard.A1.Flex (1 OCPU ARM / 6 GB RAM), free tier eligible
- **OS**: Oracle Linux 9 (aarch64), Oracle-sourced image
- **Python**: dnf-installed (`python3`, `python3-pip`), no uv
- **Process management**: systemd unit (`tmi-tf-wh.service`)
- **Application**: FastAPI + Uvicorn HTTP server

### Networking

- **VCN** with public subnet (load balancer) and private subnet (compute)
- **OCI Load Balancer** (flexible, 10 Mbps min, free tier eligible):
  - HTTPS listener on port 443 with TLS certificate
  - Routes to compute instance on private subnet via HTTP
  - Health check: `GET /health` every 30s
- **NAT Gateway** for outbound internet from private subnet (LLM APIs, GitHub, TMI)
- **Security lists**: inbound 443 on public subnet; inbound from LB only on private subnet; outbound to internet on private subnet

### Queue

- **OCI Queue** for durable job dispatch between webhook handler and worker pool
  - Visibility timeout: 900s (15 minutes)
  - Max delivery attempts: 3
  - Dead letter queue for failed jobs
  - Retention: 24 hours

### Secrets

- **OCI Vault** with master encryption key, accessed via instance principal (IMDS)
  - `webhook-secret` → `WEBHOOK_SECRET`
  - `tmi-client-id` → `TMI_CLIENT_ID`
  - `tmi-client-secret` → `TMI_CLIENT_SECRET`
  - `llm-api-key` → `LLM_API_KEY` (mapped to provider-specific env var by config.py)
  - `github-token` → `GITHUB_TOKEN` (optional)

### IAM

- Dynamic group matching the compute instance OCID
- Policies: read secrets in vault, use queues, read/delete queue messages

### Observability

- **OCI Unified Monitoring Agent** installed on the instance, configured to push application logs to OCI Logging
- **Structured JSON logging** to stdout → journald → OCI Logging
- Log levels: INFO for normal flow (webhook received, job started, phase complete), WARNING for retries/transient errors, ERROR for job failures
- INFO-level events include full webhook headers and payload

## Webhook Handling

### Supported Events

The service accepts TMI webhook POSTs for any of these event types:

- `threat_model.created`
- `threat_model.updated`
- `repository.created`
- `repository.updated`
- `addon.invoked`

### Trigger Logic

Regardless of event type:
- If the payload includes a specific repository ID (`resource_id` where `resource_type` is a repository), analyze only that repository
- If no repository ID is present, analyze all repositories in the threat model that have GitHub URLs (filtered by `is_github_url()`, consistent with existing CLI behavior)

### Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/webhook` | POST | Main webhook receiver |
| `/health` | GET | Load balancer health check |
| `/status` | GET | Current job status for debugging |

### Request Flow

1. Load balancer terminates TLS, forwards HTTP to instance
2. FastAPI receives POST `/webhook`
3. Log full request headers and payload at INFO level
4. Read raw body, verify HMAC signature (`X-Webhook-Signature` header, SHA256, using `WEBHOOK_SECRET`). Reject with 401 if invalid.
5. Parse JSON payload
6. If `type` is `webhook.challenge`: respond with `{"challenge": "<value>"}` and return
7. Extract `threat_model_id`, `resource_id` (optional), `event_type`, `callback_url` (addon only), `invocation_id` (addon only)
8. Publish job message to OCI Queue
9. Return `200 {"status": "accepted"}`

### HMAC Verification

```python
import hmac
import hashlib

def verify_webhook(raw_body: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(
        secret.encode('utf-8'),
        raw_body,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, f"sha256={expected}")
```

Signature is in the `X-Webhook-Signature` header, format `sha256=<hex_digest>`.

## Job Processing

### Worker Pool

- Async worker pool using asyncio tasks
- Polls OCI Queue for messages
- **Configurable max concurrency**: `MAX_CONCURRENT_JOBS`, default 3
- Each job gets an isolated temp directory (`/tmp/tmi-tf-<job-id>/`), cleaned up on completion

### Job Lifecycle

1. Worker dequeues message from OCI Queue
2. Create temp directory `/tmp/tmi-tf-<job-id>/`
3. If addon invocation: send callback `in_progress` to `callback_url`
4. Authenticate with TMI via client_credentials
5. Fetch threat model
6. Update TMI status note: "Analysis starting..."
7. Determine repos to analyze:
   - If `resource_id` present: fetch and analyze only that repo
   - Otherwise: fetch and analyze all repos (up to `MAX_REPOS`)
8. For each repo:
   a. Sparse clone to job temp dir (`.tf` and `.tfvars` files only)
   b. Detect Terraform environments
   c. Analyze all environments found — behavioral change from CLI which prompts for one. In server mode, every detected environment is analyzed and included in the reports.
   d. Phase 1: Inventory extraction
   e. Phase 2: Infrastructure analysis
   f. Phase 3: Security analysis (STRIDE)
   g. Update status note with progress
9. Generate reports → create/update TMI notes
10. Generate DFD → create/update TMI diagram
11. Create threat objects
12. Update status note: "Complete"
13. If addon invocation: send callback `completed`
14. Delete queue message
15. Clean up temp directory

### Error Handling

| Failure | Behavior |
|---------|----------|
| HMAC verification fails | 401, not enqueued |
| Invalid payload | 400, not enqueued |
| Queue publish fails | 500, TMI retries delivery |
| Vault unreachable at startup | Service fails to start, systemd retries |
| TMI auth fails during job | Job fails, message returns to queue after visibility timeout, retried up to 3x then DLQ |
| LLM API error | retry.py handles transient errors; persistent failure → job fails → DLQ |
| Git clone fails | Job fails for that repo, continues with remaining repos |
| Worker crashes mid-job | Queue message becomes visible after timeout → reprocessed |
| Service process crashes | systemd restarts, workers resume polling, unfinished jobs reprocessed |

On any job failure:
- Update TMI status note with error details
- If addon invocation: send callback `failed`

### Status Reporting

Three channels, always active where applicable:

1. **TMI Status Note** (always): progress updates in the threat model
2. **Addon Callback** (addon.invoked only): `in_progress` → `completed`/`failed` via `callback_url`, signed with HMAC
3. **GET /status** (on request): current jobs, queue depth, worker pool state

## Code Changes

### New Modules

| Module | Responsibility |
|--------|---------------|
| `server.py` | FastAPI app. POST /webhook, GET /health, GET /status. Starts worker pool on startup. |
| `webhook_handler.py` | HMAC signature verification, challenge response, payload parsing into Job objects. |
| `queue_client.py` | Wraps OCI Queue SDK. Publish, consume, delete messages, extend visibility. |
| `worker.py` | Async worker pool. Polls queue, manages concurrency semaphore, dispatches to analyzer. |
| `job.py` | Job dataclass: threat_model_id, repo_id, event_type, callback_url, invocation_id, temp_dir. |
| `vault_client.py` | Fetches secrets from OCI Vault at startup via instance principal (IMDS) or ~/.oci/config (dev). |
| `addon_callback.py` | Sends status updates to TMI callback URL with HMAC signature. |
| `analyzer.py` | Extracted analysis pipeline from cli.py. Shared by CLI and webhook worker. |

### Modified Modules

| Module | Changes |
|--------|---------|
| `config.py` | Add server config vars (MAX_CONCURRENT_JOBS, QUEUE_OCID, VAULT_OCID, SERVER_PORT, WEBHOOK_SECRET, LLM_API_KEY, TMI_CLIENT_PATH). Support Vault-sourced secrets. Map LLM_API_KEY to provider-specific env var: after Vault secrets are loaded, set `os.environ["ANTHROPIC_API_KEY"]` (or `OPENAI_API_KEY`, etc.) from `LLM_API_KEY` based on `LLM_PROVIDER`, before existing `_validate_llm_credentials()` runs. OCI provider validation must accept instance principal (IMDS) as an alternative to `~/.oci/config`. |
| `repo_analyzer.py` | Accept per-job temp directory parameter instead of shared /tmp. Remove markdown file handling. Tighten sparse checkout to .tf and .tfvars only. |
| `tmi_client_wrapper.py` | Make TMI client path configurable. In production, load from `/opt/tmi-tf-wh/vendor/tmi-client/`. In dev, load from `~/Projects/tmi-clients/python-client-generated` (current behavior). Resolve path from `TMI_CLIENT_PATH` env var with fallback to dev default. |
| `cli.py` | Thin wrapper around analyzer.py's run_analysis(). Keeps all existing CLI functionality including browser-based PKCE auth. |

### Unchanged Modules

`auth.py`, `llm_analyzer.py`, `dfd_llm_generator.py`, `diagram_builder.py`, `threat_processor.py`, `markdown_generator.py`, `github_client.py`, `artifact_metadata.py`, `retry.py`. All prompt files unchanged.

### Core Refactor: cli.py → analyzer.py

Extract the analysis pipeline from the Click command into a standalone function:

The analysis pipeline is synchronous (LiteLLM, GitPython, requests are all sync). The `run_analysis()` function is synchronous; the async worker calls it via `asyncio.to_thread()` to avoid blocking the event loop.

```python
# analyzer.py
def run_analysis(
    config: Config,
    threat_model_id: str,
    repo_id: str | None = None,
    temp_dir: Path,
    callback: AddonCallback | None = None,
) -> AnalysisResult:
    """Run the full analysis pipeline. Used by both CLI and webhook worker."""

# cli.py — thin wrapper
@cli.command()
def analyze(threat_model_id, ...):
    result = run_analysis(config, threat_model_id, temp_dir=Path(tempfile.mkdtemp()))

# worker.py — runs sync pipeline in thread pool
async def process_job(job: Job):
    result = await asyncio.to_thread(
        run_analysis, config, job.threat_model_id, job.repo_id,
        temp_dir=job.temp_dir, callback=job.callback
    )
```

## Configuration

### Non-Secret Config (environment variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `TMI_SERVER_URL` | https://api.tmi.dev | TMI API endpoint |
| `TMI_OAUTH_IDP` | tmi | Auth flow (server mode always uses client_credentials) |
| `LLM_PROVIDER` | anthropic | LLM provider name |
| `LLM_MODEL` | (per provider default) | Model override |
| `MAX_CONCURRENT_JOBS` | 3 | Max parallel analysis jobs |
| `MAX_REPOS` | 3 | Max repos per threat model |
| `SERVER_PORT` | 8080 | Uvicorn listen port |
| `QUEUE_OCID` | (required in server mode) | OCI Queue OCID |
| `VAULT_OCID` | (required in server mode) | OCI Vault OCID |
| `CLONE_TIMEOUT` | 300 | Git clone timeout in seconds |

### Secrets (OCI Vault)

| Vault Secret Name | Maps To | Description |
|-------------------|---------|-------------|
| `webhook-secret` | `WEBHOOK_SECRET` | HMAC shared secret |
| `tmi-client-id` | `TMI_CLIENT_ID` | TMI OAuth client ID |
| `tmi-client-secret` | `TMI_CLIENT_SECRET` | TMI OAuth client secret |
| `llm-api-key` | `LLM_API_KEY` | LLM provider API key |
| `github-token` | `GITHUB_TOKEN` | GitHub PAT (optional) |

### Config Loading Order

1. Load `.env` file if present (local dev)
2. Read environment variables (systemd `Environment=` lines)
3. If `VAULT_OCID` is set: authenticate to OCI (IMDS in production, `~/.oci/config` in dev), fetch all secrets, set as env vars (overrides previous layers)
4. Map `LLM_API_KEY` to provider-specific env var based on `LLM_PROVIDER`
5. Validate required config
6. Initialize FastAPI app + worker pool

### OCI Authentication

- **Production (instance)**: Instance principal via IMDS — no credentials on disk
- **Local dev**: `~/.oci/config` file with API key authentication

## Deployment

### Instance Setup

```bash
# System packages (Oracle repos only)
sudo dnf install -y python3 python3-pip git

# Unified Monitoring Agent
sudo dnf install -y oracle-cloud-agent

# Application
sudo mkdir -p /opt/tmi-tf-wh
# deploy code via rsync, scp, or git clone
cd /opt/tmi-tf-wh
pip3 install .

# TMI client (bundled at deploy time)
# copied to /opt/tmi-tf-wh/vendor/tmi-client/

# systemd service
sudo cp deploy/tmi-tf-wh.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tmi-tf-wh
```

### systemd Unit

```ini
[Unit]
Description=TMI Terraform Webhook Analyzer
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=tmi-tf
Group=tmi-tf
WorkingDirectory=/opt/tmi-tf-wh
ExecStart=/usr/bin/python3 -m uvicorn tmi_tf.server:app --host 127.0.0.1 --port 8080
Restart=always
RestartSec=5
Environment=TMI_OAUTH_IDP=tmi
Environment=LLM_PROVIDER=anthropic
# Non-secret config as Environment= lines
# Secrets loaded from OCI Vault at startup

[Install]
WantedBy=multi-user.target
```

### Infrastructure as Code

Terraform configs in `deploy/terraform/`:

| File | Resources |
|------|-----------|
| `main.tf` | Provider config, compartment |
| `network.tf` | VCN, subnets, security lists, NAT gateway |
| `compute.tf` | Instance, cloud-init script |
| `loadbalancer.tf` | LB, listener, backend set, TLS certificate |
| `queue.tf` | OCI Queue + dead letter queue |
| `vault.tf` | Vault, master key, secrets |
| `iam.tf` | Dynamic group, policies |
| `logging.tf` | OCI Logging log group, log, agent config |
| `variables.tf` | Configurable inputs |
| `outputs.tf` | LB public IP, instance OCID, queue OCID |

### Logging Pipeline

1. Application writes structured JSON logs to stdout
2. journald captures stdout from systemd service
3. OCI Unified Monitoring Agent reads from journald
4. Agent pushes to OCI Logging service
5. Logs viewable in OCI Console, searchable, alertable

### Dependencies

Existing `pyproject.toml` plus new dependencies:

- `fastapi` — HTTP framework
- `uvicorn` — ASGI server
- `oci` — OCI SDK (already present for OCI LLM provider)

No new external runtime sources. `oci` SDK is already a dependency.
