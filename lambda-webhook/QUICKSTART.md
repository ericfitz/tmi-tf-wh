# TMI Terraform Analyzer - Lambda Webhook Quick Start

This is a condensed quick-start guide. For comprehensive deployment instructions, see [DEPLOYMENT.md](DEPLOYMENT.md).

## What This Is

Converts the tmi-tf CLI tool into an AWS Lambda function triggered by TMI webhooks. When a Terraform repository is created or updated in TMI, the Lambda function automatically:

1. Receives webhook from TMI
2. Authenticates with OAuth client credentials
3. Clones the repository (Terraform files only)
4. Analyzes with Claude Sonnet 4.5
5. Creates a note in the TMI threat model with analysis results

## Architecture

```
TMI Webhook → API Gateway (webhook.tmi.dev)
  ↓
Receiver Lambda (validate + enqueue)
  ↓
SQS Queue
  ↓
Analyzer Lambda (clone + analyze + note)
  ↓
TMI Note (markdown report)
```

## Quick Deploy (30 minutes)

### 1. Manual Prerequisites (15 min)

```bash
# Create S3 backend
aws s3 mb s3://tmi-tf-terraform-state --region us-east-1
aws s3api put-bucket-versioning --bucket tmi-tf-terraform-state --versioning-configuration Status=Enabled

# Create DynamoDB for locks
aws dynamodb create-table \
  --table-name tmi-tf-terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region us-east-1

# Create TMI OAuth client (via TMI UI)
# → Settings → Client Credentials → Create
# → Name: "tmi-tf-lambda"

# Store credentials in Secrets Manager
aws secretsmanager create-secret \
  --name tmi-tf/oauth-credentials \
  --secret-string '{
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET",
    "anthropic_api_key": "YOUR_ANTHROPIC_KEY",
    "webhook_secret": "'$(openssl rand -hex 16)'"
  }' \
  --region us-east-1

# Request ACM certificate
aws acm request-certificate \
  --domain-name webhook.tmi.dev \
  --validation-method DNS \
  --region us-east-1

# Validate via Route 53 (ACM console → Create records in Route 53)
```

### 2. Deploy Infrastructure (10 min)

```bash
cd lambda-webhook/infrastructure/

# Initialize
terraform init

# Configure
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with ARNs from step 1

# Deploy to dev
terraform apply -var-file=environments/dev.tfvars

# Get webhook URL
terraform output webhook_url
```

### 3. Register Webhook in TMI (5 min)

```bash
# Create subscription
curl -X POST https://api.tmi.dev/api/v1/webhooks \
  -H "Authorization: Bearer YOUR_TMI_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "TMI Terraform Analyzer",
    "url": "https://webhook.tmi.dev",
    "events": ["repository.created", "repository.updated"],
    "secret": "YOUR_WEBHOOK_SECRET"
  }'

# TMI will send challenge → Lambda responds → subscription becomes active
```

### 4. Test (5 min)

```bash
# Add a Terraform repository in TMI UI
# → Threat Model → Repositories → Add Repository
# → Enter GitHub URL with .tf files

# Monitor execution
aws logs tail /aws/lambda/tmi-tf-dev-webhook-receiver --follow
aws logs tail /aws/lambda/tmi-tf-dev-analyzer --follow

# Check TMI for note: "Terraform Analysis: [repo-name]"
```

## File Structure

```
lambda-webhook/
├── README.md                      # Architecture overview
├── DEPLOYMENT.md                  # Detailed deployment guide (this is comprehensive!)
├── QUICKSTART.md                  # This file (condensed)
├── infrastructure/                # Terraform IaC
│   ├── main.tf                    # Root module
│   ├── variables.tf               # Configuration
│   ├── outputs.tf                 # Outputs
│   ├── backend.tf                 # S3 + DynamoDB backend
│   ├── modules/                   # Reusable modules
│   │   ├── api_gateway/           # HTTP API + custom domain
│   │   ├── lambda/                # Receiver + analyzer functions
│   │   ├── sqs/                   # Queue + DLQ + alarms
│   │   ├── dynamodb/              # Idempotency table
│   │   └── secrets/               # Secrets Manager access
│   └── environments/
│       ├── dev.tfvars             # Dev config
│       └── prod.tfvars            # Prod config (with canary)
└── lambda/
    ├── receiver/                  # Webhook receiver
    │   ├── handler.py             # HMAC validation, idempotency, SQS enqueue
    │   └── requirements.txt
    └── analyzer/                  # Terraform analyzer
        ├── handler.py             # OAuth auth, git clone, Claude analysis
        ├── lambda_auth.py         # OAuth client credentials
        ├── lambda_config.py       # Config from Secrets Manager
        ├── lambda_markdown.py     # Webhook report generator
        ├── requirements.txt
        └── tmi_tf/                # Copied from root (original CLI code)
```

## Key Features

- **Serverless**: No servers to manage
- **Event-driven**: Triggered by TMI webhooks
- **Async**: SQS decouples webhook receipt from analysis
- **Secure**: HMAC validation, OAuth credentials in Secrets Manager
- **Observable**: CloudWatch logs, X-Ray tracing, alarms
- **Cost-effective**: ~$0.28 per analysis (97% is Claude API)
- **Idempotent**: DynamoDB prevents duplicate processing
- **Resilient**: Automatic retries, DLQ for failures

## Cost

| Analysis Volume | Monthly Cost |
|-----------------|--------------|
| 10 repos        | $3.78        |
| 100 repos       | $29.75       |
| 1,000 repos     | $282.50      |

**Breakdown**: 97% Claude API, 2% Lambda, 1% AWS services

## Monitoring

### CloudWatch Logs

```bash
# Receiver
aws logs tail /aws/lambda/tmi-tf-dev-webhook-receiver --follow

# Analyzer
aws logs tail /aws/lambda/tmi-tf-dev-analyzer --follow
```

### Metrics

```bash
# Lambda invocations
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=tmi-tf-dev-analyzer \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

### Alarms

- **Critical**: DLQ depth > 0 (analysis failures)
- **Warning**: Queue depth > 100, message age > 1 hour

## Troubleshooting

| Issue | Fix |
|-------|-----|
| **401 Unauthorized** | Verify webhook secret in Secrets Manager matches TMI subscription |
| **Analysis timeout** | Increase `analyzer_lambda_timeout` and `analyzer_lambda_ephemeral_storage` |
| **Messages in DLQ** | Check analyzer logs, fix issue, re-drive messages |
| **No note created** | Check CloudWatch logs for errors, verify TMI API credentials |

## Next Steps

1. **Production deployment**: Use `environments/prod.tfvars` with canary
2. **Multi-region**: Deploy to us-west-2 for DR
3. **CI/CD**: GitHub Actions for automated deployments
4. **Monitoring**: CloudWatch dashboard with key metrics
5. **Cost optimization**: Use Claude Haiku for simple repos

## Resources

- **README.md**: Architecture details, component descriptions
- **DEPLOYMENT.md**: Comprehensive deployment guide
- **Plan**: `.claude/plans/` - original implementation plan
- **TMI Docs**: Webhook API, OAuth integration

## Original CLI Tool

The original CLI tool remains **completely unchanged** in the repository root:

```bash
# Original CLI still works
cd /Users/efitz/Projects/tmi-tf
uv run tmi-tf analyze THREAT_MODEL_ID
```

All Lambda-specific code is isolated in `lambda-webhook/` subdirectory.

## Support

- **Logs**: CloudWatch Logs (/aws/lambda/tmi-tf-*)
- **Traces**: AWS X-Ray console
- **Metrics**: CloudWatch Metrics (AWS/Lambda, AWS/SQS)
- **DLQ**: SQS dead letter queue for failed messages
