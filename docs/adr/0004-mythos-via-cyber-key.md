# ADR 0004: Cyber key for ANTHROPIC_CVP_API_KEY, Mythos 5.2, model-named profiles

- Status: Accepted
- Date: 2026-11-20
- Decision maker: Eric Fitzgerald (human decision)
- Amends: ADR 0003 (its "leave Mythos out" item)

## Context

ADR 0003 left Mythos out because no deployed Anthropic key could reach it.
`~/.keys/ANTHROPIC_API_KEY_CYBER` (it exports `ANTHROPIC_API_KEY`) can reach
`claude-mythos-5-2` and every other Anthropic profile model (HTTP 200 on
2026-11-20).

## Decision

- Fill the production Secret's `ANTHROPIC_CVP_API_KEY` from
  `~/.keys/ANTHROPIC_API_KEY_CYBER`; `scripts/sync-llm-keys-aws.sh` maps it.
  The Secret key name stays the same, so no profile changes for this.
- Add profiles for claude-mythos-5-2 and claude-fable-5-2 (Anthropic) and
  gpt-6.2-astra, gpt-6.2-sol, gpt-6.1-sol, gpt-6.1-terra (OpenAI, Responses
  API).
- Do not add gpt-6.1-astra: it returned HTTP 404 on 2026-11-20.
- Name every profile after its provider model name, with `.` replaced by `_`
  (`gpt-6.2-astra` -> `gpt-6_2-astra`, `claude-mythos-5-2` unchanged). The
  profile-name pattern stays `^[a-z0-9][a-z0-9_-]{0,63}$`; no code change.
  The old short names (`fable51`, `gpt6sol`, ...) are removed, not aliased.
- Make `claude-fable-5-2` the default: `LLM_PROFILE` (`llm_profile`) and the
  default of the addon's `profile` picker parameter.
- Declare an enum parameter `profile` on the tmi-tf-wh addon in TMI listing
  every profile, so tmi-ux offers a picker. PATCH /addons/{id} is
  admin-only, so Eric applies it.

## Consequences

- Every Anthropic profile now runs on the cyber key. If that key rotates,
  re-run `scripts/sync-llm-keys-aws.sh`.
- The new profiles reach production only with the next image deploy, because
  production reads `llm-profiles.yaml` from the image. The image tag and
  `llm_profile` must change in the same apply: the old default name does not
  exist in the new image, and the new one does not exist in the old image.
- The addon enum must be updated after that deploy, and again whenever a
  profile is added or removed (TMI rejects a value not in `enum_values`).
- Invocations or local `.env` files that name an old short profile fail with
  an unknown-profile error.
