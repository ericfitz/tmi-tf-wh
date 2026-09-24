# mythos5 vs gpt56cyber: aws-public analysis comparison

2026-09-24. Both runs analyzed `ericfitz/tmi`, environment `aws-public`, on image 6515c77 against TMI 1.14.6 (api.tmi.dev), writing to threat model 02909291. The TM was cleaned before run 1 and not cleaned between runs, so it now holds both runs' output side by side.

| Run | Profile | Model | Delivery | Result |
|---|---|---|---|---|
| 1 | gpt56cyber | openai/responses/gpt-5.6-cyber | 01a0d1ab | delivered, 1 succeeded, 0 failed |
| 2 | mythos5 | anthropic/claude-mythos-5 | 01a0d1bd | delivered, 1 succeeded, 0 failed |

## Metrics

| | gpt56cyber | mythos5 |
|---|---|---|
| Components / services (phase 1) | 102 / 2 | 96 / 2 |
| Relationships / data flows (phase 2) | 25 / 11 | 43 / 16 |
| Threats (critical / high / medium) | 18 (4 / 13 / 1) | 24 (4 / 12 / 8) |
| DFD | 34 components, 22 flows, 71 cells | 45 cells |
| Analysis time | 670 s | 772 s |
| Tokens (phases 1-3) | 562k | 1.22M |
| Cost incl. DFD | ~$12.25 | ~$16.13 |

## Bug verification

- **#77 (threat metadata):** fixed. Threats carry llm-profile, llm-model, llm-provider, token, cost, and creation metadata.
- **#79 (disallowed CWEs):** neither model returned a CWE outside CWE-699/CWE-1446, so the corrective turn never fired and no CWEs were dropped. The retry path is still unexercised in prod.
- **#73 (409 on artifact metadata):** closed. Since #78 every run creates its own notes and diagram, so run 2 set metadata on all of them with zero 409s.

## Findings

Each cell shows severity and score as that model rated the finding. A dash means the model didn't find it.

| # | Finding | gpt56cyber | mythos5 |
|---|---|---|---|
| 1 | Unpinned `:latest` Fluent Bit (privileged logging agent) image | Critical 9.5 | Critical 9.5 |
| 2 | Weak network segmentation: unrestricted node-to-node traffic | Critical 9.4 | Critical 9.3 |
| 3 | NATS messaging unauthenticated / plaintext (mythos: with Redis) | Critical 9.3 | High 8.6 |
| 4 | No rotation for high-value secrets (DB, Redis, JWT, settings key) | High 8.9 | Critical 9.1 |
| 5 | EKS management API reachable from 0.0.0.0/0 | High 8.7 | Medium 6.9 |
| 6 | Every authenticated user gets security-reviewer privileges | High 8.6 | High 8.7 |
| 7 | Plaintext HTTP (port 80) accepted at the public ALB | High 8.8 | High 7.6 |
| 8 | ALB-to-backend traffic unencrypted | High 7.6 | Medium 5.9 |
| 9 | Unrestricted workload/node internet egress | High 8.4 | High 7.1 |
| 10 | No WAF, rate limiting, or DDoS protection on the ALB | High 8.7 | High 8.7 |
| 11 | Mutable ECR image tags | High 8.5 | High 8.5 (combined with #12) |
| 12 | ECR `force_delete` lets teardown irreversibly delete images | High 8.3 | Yes (in #11) |
| 13 | RDS without deletion protection or final snapshot | High 8.3 | High 8.3 |
| 14 | RDS single-AZ | Yes (in #13) | High 8.9 (with #15) |
| 15 | RDS without Enhanced Monitoring / Performance Insights | - | Yes (in #14) |
| 16 | Single NAT gateway is an availability single point of failure | High 8.2 | High 8.2 |
| 17 | EKS control-plane audit logging disabled | Medium 5.3 | Medium 5.3 |
| 18 | Load Balancer Controller IAM can modify account-wide edge resources | Critical 9.4 | - |
| 19 | Runtime application uses PostgreSQL master credentials | High 8.4 | - |
| 20 | Database storage exhaustion is uncontained | High 8.3 | - |
| 21 | Helm chart fetched without integrity verification | - | Critical 9.0 |
| 22 | Sensitive secrets persisted in Terraform state | - | High 8.5 |
| 23 | Fluent Bit DaemonSet lacks pod security hardening | - | High 8.5 |
| 24 | EKS secrets not envelope-encrypted with KMS | - | High 7.0 |
| 25 | Route 53 validation records use `allow_overwrite` | - | High 7.0 |
| 26 | Database subnets routed to the internet via NAT | - | High 7.0 |
| 27 | No VPC Flow Logs | - | Medium 6.9 |
| 28 | Broad NodePort range (30000-32767) open from ALB to nodes | - | Medium 6.3 |
| 29 | Log collection limited to TMI containers, 30-day retention | - | Medium 4.8 |

Rows 11-15 merge findings that the two models split differently. For example, mythos5 reported mutable tags and `force_delete` as one finding, and gpt56cyber folded single-AZ into its RDS safeguards finding.

## Takeaways

- **Overlap:** 16 of 29 findings (rows 1-14, 16, 17) were found by both models, at least in part. On those, severities mostly agree. gpt56cyber rates the network-exposure items higher: EKS API, ALB-to-backend plaintext, and NATS.
- **mythos5 covers more ground.** It found 10 findings that gpt56cyber missed (rows 15 and 21-29). These cluster in supply chain (Helm integrity), secrets handling (Terraform state, KMS), and logging and monitoring (Flow Logs, retention, RDS monitoring). The cost is about 30% more money and 2.2x the tokens.
- **gpt56cyber finds sharper IAM and data-layer issues.** It found 3 that mythos5 missed, including a critical one on the Load Balancer Controller's account-wide permissions and the app's use of Postgres master credentials. It also produced a denser DFD (71 vs 45 cells).
- The two runs are complementary. Neither model's findings are a superset of the other's.
