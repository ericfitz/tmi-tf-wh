# ADR 0003: Drop the cyber API keys and cyber-model profiles

- Status: Accepted
- Date: 2026-10-09
- Decision maker: Eric Fitzgerald (human decision)

## Context

Production held two weekly-rotating "cyber" keys (`OPENAI_CYBER_API_KEY`,
`ANTHROPIC_CYBER_API_KEY`) that gave access to Mythos and the gpt-*-cyber
models. Every other profile also used them.

## Decision

Eric removed both cyber keys from the EKS deployment and asked for:

- Delete the `gpt56cyber` and `astracyber` profiles.
- Move the Anthropic profiles to `ANTHROPIC_CVP_API_KEY`, now filled from
  `~/.keys/ANTHROPIC_AWS_API_KEY`.
- Move the non-cyber OpenAI profiles (gpt6astra, gpt6sol, gpt56terra,
  gpt6luna) to a new `OPENAI_API_KEY`, filled from `~/.keys/OPENAI_API_KEY`.
  `daybreakblue` is deleted because that key cannot reach its model.
- Make `fable51` the default profile.
- Leave Mythos out. Eric asked for a `mythos51` profile, but neither Anthropic
  key can reach `claude-mythos-5-1` (HTTP 404 on 2026-10-09). Add it once a
  key has access.

## Consequences

- An invocation that names a removed profile fails before any clone or LLM call.
- `scripts/sync-llm-keys-aws.sh` tracks only the two remaining keys. Nothing
  rotates weekly any more.
