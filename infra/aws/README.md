# AWS deployment (EKS)

Deploys `tmi-tf-wh` into the existing TMI EKS cluster and exposes it at
`https://webhook.tmi.dev/tf/webhook`. Design: `docs/superpowers/specs/2026-09-04-aws-eks-deployment-design.md`.

## Prerequisites

- AWS CLI with profile `tmi`; Terraform >= 1.5; Docker with buildx; kubectl.
- The TMI cluster `tmi-eks` (us-east-1) with the AWS Load Balancer Controller
  installed, and the `tmi.dev` hosted zone in the same account.
- A kubectl context named `tmi-eks`:
  `aws eks update-kubeconfig --name tmi-eks --region us-east-1 --profile tmi --alias tmi-eks`

## First deploy

```bash
cd infra/aws
cp backend.hcl.example backend.hcl
cat > secrets.auto.tfvars <<'EOF'
webhook_secret    = "<random 32+ char string>"
tmi_client_id     = "<from TMI, see below>"
tmi_client_secret = "<from TMI, see below>"
llm_api_key       = "<Anthropic API key>"
github_token      = ""
EOF

terraform init -backend-config=backend.hcl
terraform apply -target=aws_ecr_repository.this   # repo must exist before the push
../../scripts/push-aws.sh                          # builds linux/amd64, pushes :latest
terraform apply                                    # everything else
terraform output webhook_url
```

Optional non-secret overrides go in `terraform.tfvars` (copy
`terraform.tfvars.example`); every non-secret variable has a default.

The first full apply takes a few minutes: ACM validates the certificate via
DNS, then the controller provisions the ALB, then the CNAME is written.

Verify:

```bash
curl -s https://webhook.tmi.dev/tf/health
kubectl --context tmi-eks -n tmi-tf get pods,ingress
```

## TMI-side wiring (manual, once)

1. In TMI, create an OAuth client with the `client_credentials` grant for this
   service. Put its id/secret in `secrets.auto.tfvars` and re-apply.
2. Create a webhook subscription whose target is the `webhook_url` output and
   whose shared secret equals `webhook_secret`. TMI sends a challenge; the app
   answers it automatically.

## Redeploying a new image

```bash
../../scripts/push-aws.sh --tag <git-sha>
terraform apply -var app_image_tag=<git-sha>
```

Pushing `:latest` and re-applying does not restart the pod (the spec is
unchanged); use a unique tag, or
`kubectl --context tmi-eks -n tmi-tf rollout restart deploy/tmi-tf-wh`.

## Adding another webhook app to `webhook.tmi.dev`

The hostname is served by one ALB shared through the IngressGroup
`tmi-webhooks`. To add an app:

1. Give it a unique path prefix (this app owns `/tf`) and have it serve its
   routes under that prefix.
2. Create an Ingress in the app's own namespace with
   `alb.ingress.kubernetes.io/group.name: tmi-webhooks`, `scheme: internet-facing`,
   `ingressClassName: alb`,
   `target-type: ip`, `listen-ports: [{"HTTPS":443}]`, the same
   `certificate-arn`, a `healthcheck-path` under its prefix, and a
   `pathType: Prefix` rule for its prefix.
3. Nothing in this repo changes. The certificate and the Route53 CNAME are
   currently owned by this stack (`dns.tf`); when a second app exists, move
   them to a shared stack with `terraform state mv` / `import`.

## Tear down

```bash
terraform destroy
```

Destroying removes the ALB only if no other Ingress remains in the group.
The Load Balancer Controller deletes the ALB asynchronously, so the first
`terraform destroy` can fail on the ACM certificate being "in use"; re-run
`terraform destroy` after a minute.
