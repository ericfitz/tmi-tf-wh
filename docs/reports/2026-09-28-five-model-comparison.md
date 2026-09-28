# Five-model comparison: aws-public analysis + Jev eval

2026-09-28 (overnight, run autonomously). Each profile analyzed `ericfitz/tmi`, environment `aws-public`, on image 1211566 against TMI 1.15.6, writing into the wiped threat model f902cdbb ("Security Review - TMI Terraform Templates"). The runs ran one after another, and the TM now holds all five runs' notes, diagrams, and threats side by side. Each run's diagram name carries its model, and every threat links to its run's diagram and carries `llm-profile` metadata.

| Profile | Model | Delivery | Result |
|---|---|---|---|
| gpt56cyber | openai/responses/gpt-5.6-cyber | 01a0e628 | delivered, 1 succeeded |
| mythos5 | anthropic/claude-mythos-5 | 01a0e638 | delivered, 1 succeeded (first try 01a0e626 failed: stale key, see below) |
| gpt6sol | openai/responses/gpt-6-sol | 01a0e646 | delivered, 1 succeeded |
| fable5 | anthropic/claude-fable-5 | 01a0e64f | delivered, 1 succeeded |
| gpt6astra | openai/responses/gpt-6-astra | 01a0e65f | delivered, 1 succeeded |

All five keys worked, so no profile was skipped.

## Metrics

| | gpt56cyber | mythos5 | fable5 | gpt6astra | gpt6sol |
|---|---|---|---|---|---|
| Components / services (phase 1) | n/a (logs lost in pod roll) | 108 / 2 | 108 / 2 | 108 / 2 | 108 / 3 |
| Relationships / data flows (phase 2) | n/a | 37 / 17 | 39 / 16 | 75 / 15 | 29 / 10 |
| Threats (crit / high / med / low) | 18 (6 / 10 / 2 / 0) | 20 (7 / 9 / 2 / 2) | 24 (5 / 14 / 4 / 1) | 21 (4 / 11 / 5 / 1) | 10 (0 / 8 / 2 / 0) |
| DFD cells (edges) | 97 (38) | 48 (23) | 45 (20) | 83 (46) | 70 (34) |
| Analysis time | 703 s | 660 s | 796 s | 563 s | 384 s |
| Input / output tokens | 626k / 50k | 1.30M / 58k | 1.58M / 67k | 882k / 30k | 451k / 22k |
| Cost (analysis note) | $12.73 | $15.86 | $19.17 | $11.82 | $1.27 * |
| Jev shadow (live) | agree 1004, disagree 1 | agree 1004, disagree 1 | agree 1004, disagree 1 | agree 1004, review 1 | agree 1004, review 1 |
| Scripts and Metadata section | no findings | no findings | no findings | no findings | no findings |

\* gpt6sol's cost is what LiteLLM computed (~$0.07 per 29k-token phase-3b call). It is 10x below the others, so check that LiteLLM's price map for gpt-6-sol is right before relying on it.

Compared with 2026-09-24, gpt56cyber cost about the same ($12.25 then, $12.73 now) and mythos5 dropped slightly ($16.13 then, $15.86 now). mythos5 still uses about twice gpt56cyber's input tokens.

## Pipeline checks (#14, #79, first prod exercise)

- **#14 pipeline:** every run completed. Each analysis note has the "Scripts and Metadata" section and the "Jev shadow" job-info row. The pod logs for mythos5, gpt6sol, fable5, and gpt6astra show no `prescan failed`, `script review failed`, or omission warnings; gpt56cyber's logs were lost when the pod rolled, but its note looks the same. The aws-public tree has no risky scripts or injected metadata, so every section says "No script or metadata findings", which is correct.
- **Jev shadow (live):** Jev judged 1005 metadata strings per run, p50 of about 240 ms, 43k Jev tokens (about $0.002). The only non-agreement, in every run, was `terraform/modules/kubernetes/aws/k8s_resources.tf:132`: the CORS comment block ("NO wildcard allowed here … list exact origins"). Jev scored it noul 0.74-0.76, right at the yes/review edge, so it counted as "disagree" in 3 runs and "review" in 2. The comment is benign, so this is a borderline Jev false positive and not a missed injection.
- **#79 corrective CWE turn: first time it fired in prod.** mythos5 used CWE-522 once, and fable5 used CWE-522 and CWE-345. Each triggered exactly one retry (about $0.55), and no CWEs were dropped.
- **gpt6sol lost one threat:** phase 3a found 11 threats, but the phase-3b call for "PostgreSQL has no standby in another availability zone" returned an empty response (`finish_reason=stop`, 0 tokens). It was skipped after 1 attempt, so only 10 threats were created. A retry on an empty 3b response would have kept it; worth an issue.
- **True negative vs 09-24:** both 09-24 runs flagged the unpinned `:latest` Fluent Bit image as critical. No model flags it now, which is correct: tmi now pins `aws-for-fluent-bit:2.34.3.20260918@sha256:…`.

## Findings

Each cell shows the model's severity and score (C/H/M/L). A dash means the model didn't report it. "(in #n)" means the model folded the issue into another finding.

| # | Finding | gpt56cyber | mythos5 | fable5 | gpt6astra | gpt6sol |
|---|---|---|---|---|---|---|
| 1 | EKS API endpoint open to 0.0.0.0/0 | C 9.2 | C 9.5 | C 9.2 | M 6.9 | M 6.9 |
| 2 | Every authenticated user gets security-reviewer | H 8.6 | H 8.8 | H 7.1 | H 7.1 | H 7.1 |
| 3 | LB controller IAM can modify account-wide ELB/SG resources | C 9.4 | H 8.5 | H 8.5 | C 9.4 | H 8.5 |
| 4 | Mutable ECR image tags | H 8.5 | C 9.4 | H 8.5 | H 7.3 | H 8.5 |
| 5 | ECR `force_delete` can wipe all images | H 8.3 (with #6) | (in #4) | H 7.0 | H 7.0 | H 8.3 |
| 6 | RDS: no deletion protection / final snapshot | (in #5) | H 8.3 | H 8.3 | H 8.3 | H 8.3 |
| 7 | Unrestricted node internet egress | H 8.3 | H 7.6 | H 7.1 | M 6.8 | H 7.1 |
| 8 | RDS single-AZ, no standby | C 9.2 | (in #6) | (in #6) | H 8.9 | dropped (empty 3b) |
| 9 | Unrestricted node-to-node traffic (lateral movement) | H 8.6 | C 9.3 | H 8.6 | M 5.3 | - (see unique) |
| 10 | No secret rotation | H 7.1 | C 9.4 | C 9.1 | C 9.2 | - |
| 11 | ALB can reach the whole NodePort range | **C 9.2** | L 2.3 | L 2.3 | L 2.3 | - |
| 12 | Secrets in plaintext in TF state / copied into a k8s Secret | H 8.5 | C 9.3 + C 9.3 (2 findings) | C 9.4 | - | - |
| 13 | Postgres `sslmode=require` without server verification | C 9.0 | H 8.7 | - | C 9.1 | - |
| 14 | Single NAT gateway: cross-AZ SPOF | C 9.2 | - | - | H 8.2 | H 8.7 |
| 15 | Public ALB accepts plain HTTP :80 | H 7.6 | H 7.6 | H 7.6 | - | - |
| 16 | NATS client without TLS | H 7.4 | - | - | H 7.6 | - |
| 17 | App uses the RDS master account | H 8.5 | - | - | H 8.7 | - |
| 18 | Node role can read every ECR repo | M 6.9 | - | - | H 7.1 | - |
| 19 | No WAF / rate limiting / DDoS protection | - | H 8.7 | H 8.8 | - | - |
| 20 | EKS secrets not KMS envelope-encrypted | - | H 8.4 | H 8.3 | - | - |
| 21 | Fluent Bit runs as root with hostPath on every node | - | C 9.3 | H 8.4 | (related: no Pod Security, C 9.4) | - |
| 22 | DB subnets have NAT internet egress | - | H 7.0 | M 6.9 | - | - |
| 23 | RDS default AWS-managed key, no enhanced monitoring | - | M 5.1 | M 5.1 | - | - |
| 24 | EKS control-plane logging incomplete | - | M 5.3 | M 5.3 | - | - |

Findings only one model reported:

- **fable5:** Helm chart fetched without integrity verification (C 9.5). OIDC provider trust anchored to a fetched SHA-1 thumbprint (C 9.4). DB credentials embedded in a plaintext connection URL (H 8.5). Route 53 validation records use `allow_overwrite` (H 8.4). Application data sent to the external OpenAI API (H 8.2). 30-day audit-log retention (M 5.3).
- **gpt6astra:** app namespace doesn't enforce Pod Security (C 9.4). CNI network-management permissions on every worker (H 8.2). DB storage exhaustion with no autoscaling (H 8.3). Unauthenticated activity suppressed from logs (M 6.9). Log delivery has no durable buffering (M 6.3).
- **gpt56cyber:** no database query or change audit trail (M 5.1).
- **mythos5:** Secrets Manager secrets use the default key with no CMK access controls (L 2.1).
- **gpt6sol:** database network access granted to all EKS nodes (H 8.6). Fluent Bit excludes container logs outside a narrow filename pattern (M 5.3).

## What differs

- **Consensus core.** All five models reported #1-#7: public EKS API, reviewer-for-everyone, the LB controller's IAM scope, mutable ECR tags, ECR force_delete, RDS deletion safeguards, and open node egress. These are the highest-confidence findings.
- **The models cluster by vendor.** The two Anthropic models share seven findings that no OpenAI model reports (#12's k8s Secret copy, #19-#24). The OpenAI models share findings neither Anthropic model reports: #14 NAT SPOF (all three OpenAI models), #16 NATS TLS, #17 master DB account, and #18 ECR read-all. The OpenAI models lean toward availability and least-privilege. The Anthropic models lean toward hardening, encryption, and logging.
- **Severity calibration is the biggest disagreement.** The NodePort range (#11) is critical 9.2 for gpt56cyber and low 2.3 for the other three that report it. The public EKS API (#1) is critical for three models and medium 6.9 for gpt6astra and gpt6sol. gpt56cyber rates availability issues (NAT, single-AZ RDS) as critical and nobody else does.
- **fable5** finds the most (24) and has the most distinctive high-value findings (Helm integrity, the OIDC SHA-1 thumbprint), but it is the slowest and most expensive run ($19.17, 796 s).
- **gpt6astra** finds almost as much (21) for $11.82 in the second-shortest time (563 s), maps the most relationships (75), and produces the densest DFD. It is the best breadth per dollar among the full-price models.
- **gpt6sol** is 10x cheaper (as reported) and the fastest, but it misses secret rotation, secrets in state, and lateral movement, reports no criticals, and lost one threat to an empty response. Treat it as a cheap first pass, not a replacement.
- **mythos5 vs gpt56cyber** repeat their 09-24 pattern: mythos5 finds more encryption and secret-handling issues, and gpt56cyber more availability and privilege issues. That pattern held with a different threat count and on a changed codebase.

## Jev offline eval (frozen corpus `evals/jev`, 119 scripts / 75 metadata strings)

Per-profile reports: `docs/reports/2026-09-28-jev-vs-tmi-tf-<profile>.md`. They ran inside the prod pod (see "Overnight issues"). The Jev and static rows are the same detector in every report. The Jev metadata numbers vary by ±0.04 between runs, because Jev isn't fully deterministic.

| Detector (scripts) | Precision | Recall | F1 | Benign FP | p50 | Cost |
|---|---|---|---|---|---|---|
| static rules | 0.95 | 0.49 | 0.64 | 0.04 | 30 ms | $0 |
| Jev, fixed bands | **1.00** | 0.75 | 0.86 | 0.00 | ~140 ms | $0.004 |
| Jev, tuned threshold 0.30 (held-out half) | 0.96-0.98 | 0.91 | 0.94 | | | |
| LLM review: mythos5 | 1.00 | 0.96 | 0.98 | 0.00 | 20 s | $1.53 |
| LLM review: gpt56cyber | 0.95 | 1.00 | 0.97 | 0.09 | 17 s | $2.32 |
| LLM review: gpt6sol | 0.97 | 1.00 | **0.99** | 0.04 | 17 s | $0.22 |
| LLM review: gpt6astra | 0.97 | 0.99 | 0.98 | 0.04 | 24 s | $1.09 |
| LLM review: fable5 | invalid: refused (see below) | | | | | $0.51 |

- **Decision-rule verdict (scripts): "LLM review wins" for every valid profile.** The paired-bootstrap F1 difference (Jev minus LLM) is entirely below zero for all four: mythos5 (-0.19, -0.07), gpt56cyber (-0.19, -0.05), gpt6sol (-0.20, -0.07), gpt6astra (-0.20, -0.06). Hijack rate is a tie everywhere (0 observed on both sides). Jev's weakness is recall: 12.6% of scripts land in its "review" band, and the fixed bands count those as not flagged. At the tuned 0.30 threshold, Jev reaches F1 0.94. That is close to the LLM review, but still below it, at 1/100th of the latency and cost.
- **fable5 is not usable for script review.** Every chunk containing a malicious script comes back `finish_reason=content_filter` with empty text. The eval counts those as "not flagged", giving P 0 / R 0. Its positive F1-difference interval (0.79, 0.92) is an artifact, and the rule returns "insufficient data". Refusals are not a Jev win. The live aws-public run had no malicious scripts, so fable5 didn't hit the filter there. On a repo that does, its script review would silently find nothing. Either exclude fable5 from `script_review` or treat `content_filter` as an error.
- **Metadata (not covered by the decision rule): Jev is far better than our static injection scan.** Jev: precision 1.0, recall 0.78-0.85, F1 0.87-0.92, attacker-row miss rate 0.17-0.26. Static scan: precision 1.0, recall 0.25, F1 0.40, miss rate 0.71. There is no LLM metadata review to compare against. If Jev earns a production role anywhere, metadata injection detection is the case.

## Overnight issues and fixes

1. **The prod `ANTHROPIC_CYBER_API_KEY` was stale.** mythos5's first run (01a0e626) failed with `authentication_error: API key is invalid`. The pod's key matched neither `~/.keys/MYTHOS_API_KEY` nor `ANTHROPIC_API_KEY`, and both of those validated (HTTP 200). I replaced that one line in `infra/aws/live-secrets.auto.tfvars` from `MYTHOS_API_KEY` with a script (the value was never printed), ran `terraform plan -out` / `apply` at 04:13Z (Secret + deployment annotation changed, pod rolled), and verified the key hash in the pod. Root cause (Eric): both cyber keys (Anthropic and OpenAI) rotate weekly, usually on Friday. Eric updates `~/.keys`, and each rotation has to be replicated to the EKS Secret. I also deleted the two failure-stub notes that run left in the TM. `ANTHROPIC_CVP_API_KEY` in the pod was already correct.
2. **Jev is unreachable from Python on this Mac.** Python's TCP/TLS connect times out to both `api.typesafe.ai` and `api.tmi.dev`, while curl works and Python reaches the Anthropic and OpenAI APIs fine. That points to a local per-app or per-host network filter. Jev answered in 0.2 s from the pod, so I ran all five evals inside the pod (copied `eval_jev.py` and the frozen corpus to `/tmp/ev`; the deployed `tmi_tf` is identical to HEAD apart from `eval_jev.py`). Separately, the typesafe SDK's default per-request timeout is 10 s with a 30 s retry budget, and `evaluate_jev` aborts the whole Jev half on the first `JevError`.
3. **The webhook delivery's terminal status is `delivered`, not `completed`.** My runner script was fixed for this; no code impact.

Total LLM spend overnight is about $72: $60.85 for the live runs, $11.25 for the Jev evals (two passes of about $5.60), and under $0.20 of probes.
