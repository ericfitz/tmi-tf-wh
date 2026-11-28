# ADR 0006: Standard Anthropic key for every profile except Mythos

- Status: Accepted
- Date: 2026-11-27
- Decision maker: Eric Fitzgerald (human decision)
- Amends: ADR 0004 (its "every Anthropic profile runs on the cyber key" consequence)

## Context

ADR 0004 filled `ANTHROPIC_CVP_API_KEY` from the cyber key
(`~/.keys/ANTHROPIC_API_KEY_CYBER`) and pointed every Anthropic profile at it.
Eric wants the cyber key used only for Mythos. On 2026-11-27 the standard key
`~/.keys/ANTHROPIC_API_KEY` returned HTTP 200 for every non-Mythos Anthropic
profile model and 404 for `claude-mythos-5-2`; the cyber key returned 200 for
all of them.

## Decision

- `claude-mythos-5-2` keeps `api_key: ANTHROPIC_CVP_API_KEY`, still filled
  from `~/.keys/ANTHROPIC_API_KEY_CYBER`.
- Every other Anthropic profile uses `api_key: ANTHROPIC_API_KEY`, a new entry
  in the production Secret filled from `~/.keys/ANTHROPIC_API_KEY`.
- Any future Mythos profile uses `ANTHROPIC_CVP_API_KEY`; any other Anthropic
  profile uses `ANTHROPIC_API_KEY`.
- `scripts/sync-llm-keys-aws.sh` syncs both keys and adds a key's tfvars line
  when it is missing.

## Consequences

- Both keys must be in the Secret. A missing `ANTHROPIC_API_KEY` makes every
  non-Mythos Anthropic profile unusable (startup logs `missing key`).
- The profile change ships in the image, so the image tag and the new Secret
  entry go out in the same apply.
- Local `.env` files need `ANTHROPIC_API_KEY` for non-Mythos profiles and
  `ANTHROPIC_CVP_API_KEY` only to run Mythos.
