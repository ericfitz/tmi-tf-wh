# Fixed egress EIP and AWS logging (tmi account)

Date: 2026-09-26. Repos: `tmi` (most infra), `tmi-tf-wh` (webhooks ALB, DLQ alarm, docs).
Account 967218005408, us-east-1, AWS profile **`tmi`** for every AWS CLI / Terraform operation
(`export AWS_PROFILE=tmi`; the aws-mcp tool uses the default account and must not be used here).

## Human-made architectural decisions (Eric, 2026-09-26)

1. **The NAT egress Elastic IP `34.232.165.1` (`eipalloc-07c325e51173c0bc9`) is never released**
   unless Eric explicitly instructs it, naming the address. It survives a full undeploy/redeploy.
   Reason: an external system monitors traffic from this address.
2. The EIP moves out of the per-deployment `aws-public` stack into a new long-lived stack
   `tmi/terraform/environments/aws-persistent` (own state key, never destroyed by any script).
3. Guard layers: Terraform `prevent_destroy`; explicit IAM Deny on `ec2:ReleaseAddress` for that
   allocation; tags; Claude Code PreToolUse hook; memories / CLAUDE.md lines; source comments.
4. Logging expansion, **30-day retention everywhere**:
   - CloudTrail (multi-region, management events, log-file validation, S3 data events on writes to
     `tmi-tfstate-967218005408`), to S3 + CloudWatch Logs.
   - EventBridge → SNS email alerts to **security@tmi.dev**.
   - EKS control plane `audit` + `authenticator` logs.
   - IAM Access Analyzer (account, free).
   - VPC flow logs, ALB access logs (tmi-server ALB and `tmi-webhooks` ALB), SQS DLQ alarm.
   - RDS `postgresql` log export (with `log_connections`/`log_disconnections`).
   - **Not** doing: GuardDuty, Config, Security Hub, Resolver query logs.
5. Every step that mutates the live AWS deployment waits for Eric's explicit approval.
6. RDS `apply_immediately = true` is used only for the logging apply; it is reverted to `false`
   afterwards so future RDS changes wait for the maintenance window.

## Design

### `aws-persistent` stack (tmi repo) — account-level, outlives deployments
- `aws_eip.nat_egress`: adopted via `import {}` block; `prevent_destroy = true`; tags
  `Name=tmi-nat-eip` (kept, used for lookup), `Retain=true`, `ReleasePolicy=explicit-owner-approval-only`.
- IAM policy `deny-release-tmi-nat-eip` (Deny `ec2:ReleaseAddress` on the elastic-ip ARN), attached to
  every admin principal (today: user `llm-platform-dev`). Root cannot be restricted (no Organization).
- S3 bucket `tmi-logs-967218005408`: SSE-S3 (ALB logs require it), versioning, block public access,
  Object Lock governance 30 days, lifecycle expire current at 31 d and noncurrent at 1 d.
  Bucket policy for CloudTrail, ELB log delivery (us-east-1 ELB account `127311923021`) and
  `delivery.logs.amazonaws.com` (flow logs). Prefixes: `cloudtrail/`, `alb/tmi-server/`,
  `alb/tmi-webhooks/`, `vpc-flow/`.
- CloudTrail `tmi-trail` + CloudWatch log group `/aws/cloudtrail/tmi` (30 d) + delivery role.
- SNS topic `tmi-security-alerts`, email subscription `security@tmi.dev` (recipient must confirm).
- EventBridge rules → SNS: EC2 `ReleaseAddress`/`DisassociateAddress`/`DeleteNatGateway`;
  CloudTrail `StopLogging`/`DeleteTrail`/`UpdateTrail`/`PutEventSelectors`;
  IAM detach/delete/new version of the deny policy; root activity; console login without MFA;
  Access Analyzer active findings.
- `aws_accessanalyzer_analyzer` (ACCOUNT).
- Outputs: `nat_eip_allocation_id`, `nat_public_ip`, `log_bucket_name`, `security_alerts_topic_arn`.

### Network module / `aws-public` (tmi repo)
- `modules/network/aws`: new optional `nat_eip_allocation_id` (default `null` → module creates its own
  EIP as today, `count`-gated; `aws-private` unaffected). New optional flow-log destination var.
- `aws-public`: `data "aws_eip"` by tag `Name=tmi-nat-eip` → module. Flow log (ALL) to
  `s3://tmi-logs-.../vpc-flow/`, Parquet.
- Migration (no release): apply `aws-persistent` (import only) → `terraform state rm
  module.network.aws_eip.nat` in `aws-public` → plan to file; must show **0 destroy**, NAT gateway
  unchanged → apply the plan file.
- EKS: `enabled_cluster_log_types = ["audit","authenticator"]`; pre-create
  `/aws/eks/tmi-eks/cluster` with 30 d retention (import if it already exists).
- RDS: custom parameter group (`log_connections=1`, `log_disconnections=1`),
  `enabled_cloudwatch_logs_exports = ["postgresql"]`; pre-create
  `/aws/rds/instance/tmi-postgres/postgresql` (30 d). Changing the parameter group needs one reboot
  (short outage) — separate approval.
- tmi-server ALB access logs: `alb.ingress.kubernetes.io/load-balancer-attributes` on
  `deployments/k8s/dev/aws/ingress.yml`.
- `/tmi/tmi` pod log group already 30 d; unchanged.

### tmi-tf-wh
- `infra/aws/k8s.tf`: `load-balancer-attributes` annotation on the `tmi-webhooks` ingress
  (attributes must be identical on every ingress in the group).
- `infra/aws/sqs.tf`: CloudWatch alarm `ApproximateNumberOfMessagesVisible > 0` on
  `tmi-tf-wh-jobs-dlq` → `tmi-security-alerts` topic (looked up by name).
- Docs: `infra/aws/README.md` egress-IP note; memory update.

### Claude guardrails
- `~/.claude/settings.json` PreToolUse hook denying Bash commands that release/disassociate the EIP,
  destroy `aws-persistent`, or `state rm` the EIP; and aws-mcp scripts containing `ReleaseAddress`.
- Memories (tmi-tf-wh, tmi), one line in `~/.claude/CLAUDE.md` and `tmi/.claude/CLAUDE.md`.
- ADR in `tmi/docs/adr/` (release and recovery procedure:
  `aws ec2 allocate-address --address 34.232.165.1 --profile tmi`, immediately; works only if AWS has
  not reassigned the address).

## Constraints
- EIP is bound to us-east-1 in this account. Idle EIP costs ~$3.60/month while undeployed.
- Account has no Organization: no SCPs; root user unrestricted by IAM.
