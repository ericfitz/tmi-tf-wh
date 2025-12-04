# TMI Terraform Analyzer - Lambda Webhook Solution

This directory contains the AWS Lambda webhook solution for automated Terraform repository analysis triggered by TMI server webhooks.

## Overview

The Lambda solution converts the tmi-tf CLI tool into a serverless, event-driven architecture:

- **TMI webhook events** (repository created/updated) → **API Gateway** → **Receiver Lambda** → **SQS** → **Analyzer Lambda** → **TMI Note**

## Architecture

```
┌─────────────┐       ┌──────────────┐      ┌──────────────┐
│ TMI Server  │──────▶│ API Gateway  │─────▶│   Receiver   │
│             │webhook│webhook.tmi.dev│     │    Lambda    │
└─────────────┘       └──────────────┘      └──────┬───────┘
                                                    │
                                                    ▼
                                            ┌──────────────┐
                                            │  SQS Queue   │
                                            └──────┬───────┘
                                                    │
                                                    ▼
                                            ┌──────────────┐
                                            │   Analyzer   │
                                            │    Lambda    │
                                            └──────┬───────┘
                                                    │
                                                    ▼
                                            ┌──────────────┐
                                            │  TMI Note    │
                                            │  (Analysis)  │
                                            └──────────────┘
```

### Components

| Component | Purpose | Configuration |
|-----------|---------|---------------|
| **API Gateway HTTP API** | Webhook endpoint (webhook.tmi.dev) | Custom domain, TLS 1.2 |
| **Receiver Lambda** | Webhook validation & routing | 128MB, 10s timeout |
| **SQS Queue** | Async message queue | 16min visibility timeout, DLQ |
| **Analyzer Lambda** | Repository analysis | 3008MB, 15min timeout, 2GB /tmp |
| **DynamoDB** | Idempotency tracking | 7-day TTL, on-demand billing |
| **Secrets Manager** | OAuth credentials & API keys | client_id, client_secret, keys |

## Directory Structure

```
lambda-webhook/
├── README.md                      # This file
├── infrastructure/                # Terraform IaC
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── backend.tf
│   ├── terraform.tfvars.example
│   ├── modules/
│   │   ├── api_gateway/
│   │   ├── lambda/
│   │   ├── sqs/
│   │   ├── dynamodb/
│   │   └── secrets/
│   └── environments/
│       ├── dev.tfvars
│       └── prod.tfvars
├── lambda/
│   ├── receiver/
│   │   ├── handler.py
│   │   └── requirements.txt
│   └── analyzer/
│       ├── handler.py
│       ├── lambda_auth.py
│       ├── lambda_config.py
│       ├── lambda_markdown.py
│       └── requirements.txt
└── tests/
    ├── integration/
    └── unit/
```

## Prerequisites

### AWS Resources (Manual Setup)

1. **TMI OAuth Client Credentials**
   - Log into TMI with admin account
   - Create client credential: `tmi-tf-lambda`
   - Save `client_id` and `client_secret`

2. **AWS Secrets Manager**
   ```bash
   aws secretsmanager create-secret \
     --name tmi-tf/oauth-credentials \
     --secret-string '{
       "client_id": "your-client-id",
       "client_secret": "your-client-secret",
       "anthropic_api_key": "sk-ant-...",
       "webhook_secret": "random-32-char-secret"
     }'
   ```

3. **ACM Certificate**
   ```bash
   aws acm request-certificate \
     --domain-name webhook.tmi.dev \
     --validation-method DNS \
     --region us-east-1
   ```

4. **Terraform Backend**
   ```bash
   # S3 bucket for state
   aws s3 mb s3://tmi-tf-terraform-state
   aws s3api put-bucket-versioning \
     --bucket tmi-tf-terraform-state \
     --versioning-configuration Status=Enabled

   # DynamoDB for state locking
   aws dynamodb create-table \
     --table-name tmi-tf-terraform-locks \
     --attribute-definitions AttributeName=LockID,AttributeType=S \
     --key-schema AttributeName=LockID,KeyType=HASH \
     --billing-mode PAY_PER_REQUEST
   ```

## Deployment

### 1. Deploy Infrastructure

```bash
cd infrastructure/

# Initialize Terraform
terraform init

# Deploy to dev
terraform apply -var-file=environments/dev.tfvars

# Deploy to production (with canary)
terraform apply -var-file=environments/prod.tfvars -var="canary_weight=0.1"

# Promote to 100%
terraform apply -var-file=environments/prod.tfvars -var="canary_weight=1.0"
```

### 2. Register TMI Webhook

```bash
curl -X POST https://api.tmi.dev/webhook/subscriptions \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "tmi-tf Lambda Analyzer",
    "url": "https://webhook.tmi.dev",
    "events": ["repository.created", "repository.updated"],
    "secret": "your-webhook-secret"
  }'
```

### 3. Verify Challenge/Response

TMI will send a challenge to verify the webhook endpoint. Check CloudWatch logs:

```bash
aws logs tail /aws/lambda/tmi-tf-webhook-receiver --follow
```

## Code Reuse from Original CLI

The Lambda analyzer **reuses** the original `tmi_tf` modules without modification:

- `tmi_tf/repo_analyzer.py` - Sparse git cloning
- `tmi_tf/claude_analyzer.py` - Claude API integration
- `tmi_tf/tmi_client_wrapper.py` - TMI API client (already supports token injection)

Lambda-specific code is in `lambda-webhook/lambda/analyzer/`:

- `lambda_auth.py` - OAuth 2.0 client credentials
- `lambda_config.py` - Config from Secrets Manager
- `lambda_markdown.py` - Webhook report generator
- `handler.py` - Main Lambda handler

## Testing

### Local Testing

```bash
# Using LocalStack
docker-compose up -d localstack

# Deploy to LocalStack
cd infrastructure/
terraform init
terraform apply -var-file=test/localstack.tfvars

# Test receiver Lambda
curl -X POST http://localhost:9000/2015-03-31/functions/function/invocations \
  -d @test/webhook-challenge.json
```

### Integration Tests

```bash
cd tests/
pytest integration/
```

## Monitoring

### CloudWatch Dashboard

Dashboard: `tmi-tf-webhook-monitoring`

- Receiver Lambda: Invocations, Errors, Duration
- Analyzer Lambda: Invocations, Errors, Duration
- SQS Queue: Messages Visible, DLQ Depth
- DynamoDB: Read/Write Capacity

### CloudWatch Alarms

**Critical** (PagerDuty):
- DLQ depth > 0
- Analyzer error rate > 5%
- API Gateway 5xx > 1%

**Warning** (Email):
- Analyzer duration > 14 minutes
- SQS queue depth > 100

## Cost Estimation

### Per-Analysis Cost: ~$0.28

- Lambda (Receiver): $0.0000002
- Lambda (Analyzer): $0.0075
- Claude API: $0.27 (97% of total cost)
- SQS: $0.0000004
- API Gateway: $0.000001
- DynamoDB: $0.0000003
- Secrets Manager: $0.00014

### Monthly Scenarios

| Repos/Month | Total Cost |
|-------------|------------|
| 10 | $3.78 |
| 100 | $29.75 |
| 1,000 | $282.50 |

**Cost Optimization**: Use Claude Haiku instead of Sonnet for simpler repos (80% cost reduction).

## Troubleshooting

### DLQ Messages

```bash
# Inspect failed messages
aws sqs receive-message \
  --queue-url https://sqs.us-east-1.amazonaws.com/ACCOUNT/tmi-tf-analysis-dlq \
  --max-number-of-messages 10

# Check CloudWatch logs for error details
aws logs tail /aws/lambda/tmi-tf-analyzer --follow
```

### HMAC Signature Mismatch

- Verify webhook secret in Secrets Manager matches TMI subscription
- Check for recent secret rotation

### Analysis Timeout

- Increase `/tmp` storage to 5GB
- Check repository size (large repos may timeout)
- Review CloudWatch metrics for duration

## Security

- **HMAC Signature Verification**: All webhooks validated
- **OAuth Client Credentials**: Stored in Secrets Manager
- **IAM Least Privilege**: Lambda roles follow principle of least privilege
- **TLS 1.2+**: All connections encrypted

## Original CLI Tool

The original CLI tool remains **unchanged** in the repository root:

```bash
# Original CLI still works
cd /Users/efitz/Projects/tmi-tf
uv run tmi-tf analyze THREAT_MODEL_ID
```

## Support

- **CloudWatch Logs**: `/aws/lambda/tmi-tf-webhook-receiver` and `/aws/lambda/tmi-tf-analyzer`
- **Issues**: GitHub issues or contact security team
- **Documentation**: See implementation plan in `.claude/plans/`

## Future Enhancements

1. **Diagram Generation**: DFD generation in Lambda
2. **Multi-Region**: us-west-2 deployment for DR
3. **Cost Optimization**: Use Claude Haiku for simple repos
4. **Rate Limiting**: Per-threat-model throttling
5. **Analysis Caching**: Skip re-analysis if repo unchanged
