# ADR 0005: No pull requests; merge locally and push main

- Status: Accepted
- Date: 2026-11-26
- Decision maker: Eric Fitzgerald (human decision)

## Context

Agent work on this repo was finished by pushing a branch and opening a pull
request. The repo has one human reviewer, who approves each push in the
session anyway, so the PR step added a round trip and no extra review.

## Decision

This repo does not use pull requests. Work happens on a local branch. Once
the done gate passes and Eric approves, the branch is merged into `main`
locally and `main` is pushed. Deploys remain a separate approval.

## Consequences

- CI runs on `main` after the push, not before the merge; the local done gate
  is the only pre-merge check.
- The issue a change fixes is closed by hand once `main` is pushed.
