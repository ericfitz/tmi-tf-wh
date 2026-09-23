# Named LLM Profiles — Design

Date: 2026-09-22
Status: approved in conversation; pending written-spec review

## Problem

The deployment runs exactly one LLM configuration, set by `LLM_PROVIDER`,
`LLM_MODEL`, and a single `LLM_API_KEY` that `Config` copies into the
provider's env var. Switching models means a Terraform apply, only one
provider key can be deployed at a time, and the LiteLLM model string has to
be hand-built correctly. That last point bit us on 2026-09-18/22:
`gpt-5.6-cyber` is Responses-API-only and needs `openai/responses/gpt-5.6-cyber`,
a prefix that is easy to get wrong.

## Goal

An invoker selects both the Terraform environments and a named LLM
**profile** per invocation, for example
`{"environments": "aws", "profile": "gpt56cyber"}`. A profile carries
everything LiteLLM needs: provider, model, API flavor (chat vs responses),
authentication, and an optional base URL for a proxy. Several provider keys
coexist in the secret store; profiles reference them by name.

## Human-made architectural decisions (Eric, 2026-09-22)

These were chosen by Eric during brainstorming and must not be changed
without his approval:

1. **Profile source: file plus optional override.** A checked-in
   `llm-profiles.yaml`, built into the image and read by the CLI, is the
   default. Terraform may mount a ConfigMap that replaces it (via
   `LLM_PROFILES_FILE`).
2. **Keys are referenced by env var / secret name** in the profile
   (`api_key: OPENAI_CYBER_API_KEY`); key values never appear in profiles.
3. **Legacy variables are removed.** `LLM_PROVIDER`, `LLM_MODEL`, and
   `LLM_API_KEY` go away; profiles are the only LLM configuration path.
   `LLM_PROFILE` names the default profile.
4. **Authentication is explicit.** Every profile declares `auth`; it is never
   inferred from the presence or absence of `api_key`.

Confirmed assumptions: profiles are not secret; a configured default is used
when the invocation names none; an unknown profile or missing key fails the
invocation fast with a clear status; the CLI gets `--profile`.

## Profile file

Default path: `llm-profiles.yaml` at the repo root (copied into the image
next to `prompts/`). Override: `LLM_PROFILES_FILE`. Format: YAML, parsed with
`pyyaml` (already in `uv.lock` via LiteLLM; declared as a direct dependency).
Stdlib `tomllib` is not an option while `requires-python >= 3.10`.

```yaml
profiles:
  gpt56cyber:
    provider: openai
    model: gpt-5.6-cyber
    api: responses
    auth: api_key
    api_key: OPENAI_CYBER_API_KEY
  opus48:
    provider: anthropic
    model: claude-opus-4-8
    auth: api_key
    api_key: ANTHROPIC_API_KEY
  grok-oci:
    provider: oci
    model: xai.grok-4
    auth: oci
```

### Fields

| Field | Required | Values / meaning |
|---|---|---|
| `provider` | yes | `anthropic`, `openai`, `xai`, `gemini`, `oci` |
| `model` | yes | Bare model name, no LiteLLM prefix |
| `auth` | yes | `api_key` or `oci` (see Authentication) |
| `api_key` | iff `auth: api_key` | Name of the env var / secret holding the key |
| `api` | no | `chat` (default) or `responses`; `responses` only with `provider: openai` |
| `base_url` | no | Passed to LiteLLM as `api_base` (proxying) |

Unknown fields, unknown enum values, and violated rules are validation
errors. Profile names match `^[a-z0-9][a-z0-9_-]{0,63}$`.

### LiteLLM model string

Built, never written by hand: `{provider}/{model}`, or
`openai/responses/{model}` when `api: responses`.

### Authentication

`auth` names the credential source. Cloud values mean "that cloud's default
credential chain", which works the same on a laptop and in a pod.

| `auth` | Source | Status |
|---|---|---|
| `api_key` | `os.environ[profile.api_key]` | implemented |
| `oci` | `~/.oci/config` locally, else resource principal (current `OciLLMProvider` behavior); `OCI_COMPARTMENT_ID` from the environment | implemented |
| `aws` | AWS default chain (profile, IRSA / Pod Identity role) for `bedrock` | future |
| `gcp` | Application Default Credentials for `vertex_ai` | future |
| `azure_ad` | Entra ID / managed identity for `azure` | future |

Future values are rejected with "auth '<x>' is not supported yet". Adding one
is a new branch, not a schema change. Per-profile region/compartment
overrides are out of scope until a profile needs one.

Out of scope (YAGNI): a generic LiteLLM passthrough (temperature, reasoning
effort, max tokens). Add a field when a profile needs one.

## Module: `tmi_tf/llm_profiles.py`

- `LLMProfile` dataclass: `name`, `provider`, `model`, `auth`, `api_key`
  (var name or None), `api`, `base_url`; property `litellm_model`.
- `load_profiles(path) -> dict[str, LLMProfile]`: parse and validate; raises
  `ValueError` naming the file, profile, and field.
- `select_profile(profiles, requested: str | None) -> LLMProfile`:
  `requested`, else `LLM_PROFILE`, else error. Unknown name raises
  `ProfileError` listing available names (requested name truncated to 64
  chars in the message).
- `resolve_key(profile) -> str | None`: for `auth: api_key`, returns
  `os.environ[profile.api_key]`; missing, empty, or containing `placeholder`
  raises `ProfileError` naming the variable, never its value.

Loading happens once at process start (server and CLI). A bad file stops
startup. Startup logs each profile as usable or "missing key <VAR>" so a
missing secret is visible immediately; it does not stop startup.

## Provider construction

`get_llm_provider(profile: LLMProfile) -> LLMProvider` replaces
`get_llm_provider(config)`:

- `auth: api_key` → `ApiKeyLLMProvider(profile)`: sets
  `_extra_kwargs = {"api_key": resolve_key(profile)}` plus
  `"api_base": profile.base_url` when set. The key is passed per call and
  never written to `os.environ` (concurrent jobs may use different profiles).
- `auth: oci` → `OciLLMProvider(profile)`: current behavior, model from the
  profile.

`BaseLLMProvider.complete()` already spreads `_extra_kwargs` into
`litellm.completion()`; it does not change. `LLMProvider` gains a `profile`
property (name) for metadata.

Deleted: `LLM_PROVIDER`/`LLM_MODEL`/`LLM_API_KEY` handling in `Config`
(including the key-copying block), `DEFAULT_MODELS`, `OCI_DEFAULT_MODEL`,
`llm_provider`/`llm_model` on `Config`.

## Invocation flow

1. `webhook_handler.parse_webhook_payload` reads `data.user_data.profile`
   (trimmed non-empty string) into `result["profile"]`, beside `scope`.
2. `server.py` puts it on `Job.profile`; `Job.to_queue_message` /
   `from_queue_message` carry it.
3. `WorkerPool._run_parent` selects the profile and resolves its key
   **before** `resolve_fanout_targets` (no clone, no LLM spend on failure).
   On `ProfileError`: `callback.send_status("failed", <message>)` and return.
   On success, each child `Job` gets `profile=<resolved name>`, so every
   environment of one invocation uses the same profile even if `LLM_PROFILE`
   changes mid-invocation.
4. The child path passes the profile to `run_analysis`, which calls
   `get_llm_provider(profile)` instead of `get_llm_provider(config)`.
5. CLI: `tmi-tf analyze --profile NAME` (default `LLM_PROFILE`); errors exit
   non-zero before any clone.

Example failure statuses:
- `unknown LLM profile "gpt5cyber" (available: gpt56cyber, grok-oci, opus48)`
- `LLM profile "opus48" needs ANTHROPIC_API_KEY, which is not set`

## Metadata

`ArtifactMetadata` gains `llm-profile` alongside `llm-provider` and
`llm-model`. The status note states the profile used.

## Secrets and deployment

### AWS (`infra/aws`)

- `llm_api_key` (string) → `llm_api_keys` (`map(string)`, sensitive), keyed by
  env var name, in the untracked `live-secrets.auto.tfvars`. Merged into
  `kubernetes_secret_v1.this`; `envFrom` exposes each as its own env var.
- `llm_provider` / `llm_model` → `llm_profile` (default profile name), set as
  `LLM_PROFILE`.
- Optional `llm_profiles_yaml` (string, default `""`). When non-empty:
  a ConfigMap holding it, mounted into the pod, and `LLM_PROFILES_FILE`
  pointing at the mount. When empty: the image's file is used.
- Rollout: new image and the Terraform change in one apply (the old image
  cannot run on the new variables). Initial values: `llm_profile =
  "gpt56cyber"`, `llm_api_keys = { OPENAI_CYBER_API_KEY = <current key> }`.
  Eric runs the apply.

### OCI (`infra/oci`)

`VAULT_SECRET_MAP` loses `llm-api-key`. At startup the server extends the map
with every `api_key` named in the loaded profiles, mapping the var name to a
vault secret of the same name lower-cased with `_` → `-`
(`OPENAI_CYBER_API_KEY` → `openai-cyber-api-key`). Update `infra/oci`
(`k8s.tf`, `variables.tf`, `vault.tf`, `terraform.tfvars.example`) to match;
no OCI deploy in this work.

### Local

`.env` holds the keys under their own names plus `LLM_PROFILE`. Update
`.env.example`, `README.md`, `infra/aws/terraform.tfvars.example`,
`infra/aws/README.md`, and the "LLM providers" section of
`.claude/CLAUDE.md`.

## Testing

Unit tests (TDD):

- Loader: required fields; `auth`/`api_key` rules; `api: responses` only with
  openai; unknown fields and enum values; unsupported future `auth` values;
  bad profile names; bad YAML.
- `litellm_model` construction for chat, responses, and oci.
- Selection precedence: requested → `LLM_PROFILE` → error; unknown-name
  message lists available profiles.
- `resolve_key`: missing / empty / placeholder errors name the variable and
  never include a value.
- `ApiKeyLLMProvider`: `api_key` and `api_base` land in the `litellm.completion`
  kwargs; `os.environ` is unchanged.
- Webhook parsing of `user_data.profile`; `Job` queue round-trip.
- Worker: bad profile → `failed` callback, no fan-out; children inherit the
  resolved profile name.
- OCI secret-map extension naming.

Post-deploy check: two prod invocations on TM 02909291 with different
profiles (`gpt56cyber`, then an Anthropic profile), confirmed via the
`llm-model` / `llm-profile` artifact metadata.
