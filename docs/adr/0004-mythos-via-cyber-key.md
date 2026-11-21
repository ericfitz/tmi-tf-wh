# ADR 0004: Fill ANTHROPIC_CVP_API_KEY from the cyber key and add Mythos 5.2

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
- Add profiles `mythos52` and `fable52` (Anthropic) and `gpt62astra`,
  `gpt62sol`, `gpt61sol`, `gpt61terra` (OpenAI, Responses API).
- Do not add `gpt61astra`: `gpt-6.1-astra` returned HTTP 404 on 2026-11-20.
- `fable51` stays the default.

## Consequences

- Every Anthropic profile now runs on the cyber key. If that key rotates,
  re-run `scripts/sync-llm-keys-aws.sh`.
- The new profiles reach production only with the next image deploy, because
  production reads `llm-profiles.yaml` from the image.
