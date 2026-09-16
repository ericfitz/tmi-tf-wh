# Progress

Tracks what has been pushed. See HANDOFF.md (untracked, machine-local) for in-flight work.

- 2026-09-13 per-environment fan-out (#51): spec, plan, implementation on branch feat/per-environment-fanout; follow-up #55 completion monitoring.
- 2026-09-14 fan-out merged (#57, 916d77a) and deployed to EKS; TMI addon tmi-tf-wh registered (param `environments`).
- 2026-09-15 #58 (62fb43a): webhook allow-lists trigger events (TMI 1.10.7 `metadata.updated` caused a self-feeding job loop) and redacts token headers; deployed to EKS with the rotated OpenAI key. Verification of `environments=all` still pending (see HANDOFF.md).
- 2026-09-15 #59 (58960e2): event type read from X-Webhook-Event header (#58 had ignored all real deliveries); deployed to EKS.
- 2026-09-16 #60 (55abf05, image e89d9b4): DFD edges emitted as shape `flow` (TMI rejected `edge`, diagrams were left empty); threat text escapes TMI's XSS regexes (`on\w+\s*=` rejected prose like `deletion_protection = true`, tmi #885 filed). Deployed to EKS; verified on tmi-ux (24-cell diagram, 7/7 threats). oci-private run still fails at phase 1 (16000 output-token ceiling, #53).
- 2026-09-16 #61 (f4d3607, image e06f870): LLM calls stream via LiteLLM; output cap 64000 tokens, timeout 1200s (supported models: Opus 4.8+, Fable/Mythos 5+, GPT-5.6 sol/terra+, GPT-6 Astra, Grok 4.6+; all >=128k output). Deployed to EKS. oci-private run succeeded: phase 1 16734 output tokens (135 components), 110-cell DFD, 20/20 threats, ~$9 LLM for both jobs.
