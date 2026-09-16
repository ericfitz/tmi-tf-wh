# Progress

Tracks what has been pushed. See HANDOFF.md (untracked, machine-local) for in-flight work.

- 2026-09-13 per-environment fan-out (#51): spec, plan, implementation on branch feat/per-environment-fanout; follow-up #55 completion monitoring.
- 2026-09-14 fan-out merged (#57, 916d77a) and deployed to EKS; TMI addon tmi-tf-wh registered (param `environments`).
- 2026-09-15 #58 (62fb43a): webhook allow-lists trigger events (TMI 1.10.7 `metadata.updated` caused a self-feeding job loop) and redacts token headers; deployed to EKS with the rotated OpenAI key. Verification of `environments=all` still pending (see HANDOFF.md).
- 2026-09-15 #59 (58960e2): event type read from X-Webhook-Event header (#58 had ignored all real deliveries); deployed to EKS.
