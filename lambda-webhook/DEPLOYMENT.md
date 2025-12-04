# TMI Terraform Analyzer - Lambda Webhook Deployment Guide

This guide provides step-by-step instructions for deploying the Lambda webhook solution to AWS.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Manual AWS Setup](#manual-aws-setup)
3. [Terraform Deployment](#terraform-deployment)
4. [TMI Webhook Registration](#tmi-webhook-registration)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Tools

```bash
# Install Terraform
brew install terraform

# Install AWS CLI
brew install awscli

# Configure AWS credentials
aws configure
```

### Required Information

Before starting, gather the following:

- **AWS Account ID**: Your AWS account number
- **Route 53 Zone ID**: For tmi.dev domain (find in Route 53 console)
- **TMI OAuth Credentials**: Client ID and client secret from TMI
- **Anthropic API Key**: For Claude API access
- **Webhook Secret**: Generate a random 32-character string

---

## Manual AWS Setup

These resources must be created manually before running Terraform.

### 1. Create Terraform Backend

```bash
# S3 bucket for Terraform state
aws s3 mb s3://tmi-tf-terraform-state --region us-east-1

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket tmi-tf-terraform-state \
  --versioning-configuration Status=Enabled

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket tmi-tf-terraform-state \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

# DynamoDB table for state locking
aws dynamodb create-table \
  --table-name tmi-tf-terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region us-east-1
```

### 2. Create TMI OAuth Client Credentials

1. Log into TMI with admin account
2. Navigate to **Settings** → **Client Credentials**
3. Click **Create Client Credential**
4. Enter:
   - **Name**: `tmi-tf-lambda`
   - **Description**: `Lambda webhook analyzer for automated Terraform analysis`
5. Save the `client_id` and `client_secret` securely

### 3. Generate Webhook Secret

```bash
# Generate a random 32-character secret
openssl rand -hex 16
```

### 4. Store Credentials in AWS Secrets Manager

```bash
# Create secret
aws secretsmanager create-secret \
  --name tmi-tf/oauth-credentials \
  --description "OAuth credentials and API keys for TMI Terraform analyzer" \
  --secret-string '{
    "client_id": "YOUR_TMI_CLIENT_ID",
    "client_secret": "YOUR_TMI_CLIENT_SECRET",
    "anthropic_api_key": "YOUR_ANTHROPIC_API_KEY",
    "webhook_secret": "YOUR_WEBHOOK_SECRET"
  }' \
  --region us-east-1

# Save the secret ARN - you'll need this for Terraform
```

### 5. Request ACM Certificate

```bash
# Request certificate (must be in us-east-1 for API Gateway)
aws acm request-certificate \
  --domain-name webhook.tmi.dev \
  --validation-method DNS \
  --region us-east-1

# Note the certificate ARN
```

**DNS Validation**:

1. Go to ACM console → Certificates → webhook.tmi.dev
2. Click **Create records in Route 53**
3. Wait for validation (usually 5-10 minutes)

### 6. Find Route 53 Zone ID

```bash
# List hosted zones
aws route53 list-hosted-zones

# Look for tmi.dev and note the zone ID
# Example: /hostedzone/Z0123456789ABCDEFGHIJ
```

---

## Terraform Deployment

### 1. Prepare Configuration

```bash
cd lambda-webhook/infrastructure/

# Copy example tfvars
cp terraform.tfvars.example terraform.tfvars

# Edit terraform.tfvars with your values
vim terraform.tfvars
```

**Required values in terraform.tfvars**:

```hcl
route53_zone_id     = "Z0123456789ABCDEFGHIJ"  # From step 6 above
acm_certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/abc-def-123"  # From step 5 above
secrets_manager_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:tmi-tf/oauth-credentials-AbCdEf"  # From step 4 above
alarm_email         = "devops@example.com"  # Your email for alarms
```

### 2. Deploy to Development

```bash
# Initialize Terraform
terraform init

# Validate configuration
terraform validate

# Plan deployment (review changes)
terraform plan -var-file=environments/dev.tfvars \
  -var="route53_zone_id=Z0123456789ABCDEFGHIJ" \
  -var="acm_certificate_arn=arn:aws:acm:..." \
  -var="secrets_manager_arn=arn:aws:secretsmanager:..."

# Apply (create resources)
terraform apply -var-file=environments/dev.tfvars \
  -var="route53_zone_id=Z0123456789ABCDEFGHIJ" \
  -var="acm_certificate_arn=arn:aws:acm:..." \
  -var="secrets_manager_arn=arn:aws:secretsmanager:..."

# Save outputs
terraform output > outputs.txt
```

### 3. Deploy to Production

```bash
# Plan with production config
terraform plan -var-file=environments/prod.tfvars \
  -var="route53_zone_id=Z0123456789ABCDEFGHIJ" \
  -var="acm_certificate_arn=arn:aws:acm:..." \
  -var="secrets_manager_arn=arn:aws:secretsmanager:..." \
  -var="alarm_email=devops@example.com"

# Apply with canary (10% traffic to new version)
terraform apply -var-file=environments/prod.tfvars \
  -var="route53_zone_id=Z0123456789ABCDEFGHIJ" \
  -var="acm_certificate_arn=arn:aws:acm:..." \
  -var="secrets_manager_arn=arn:aws:secretsmanager:..." \
  -var="alarm_email=devops@example.com"

# Monitor CloudWatch metrics for 30 minutes

# If healthy, promote to 100%
terraform apply -var-file=environments/prod.tfvars \
  -var="route53_zone_id=Z0123456789ABCDEFGHIJ" \
  -var="acm_certificate_arn=arn:aws:acm:..." \
  -var="secrets_manager_arn=arn:aws:secretsmanager:..." \
  -var="alarm_email=devops@example.com" \
  -var="canary_weight=1.0"
```

---

## TMI Webhook Registration

### 1. Obtain JWT Token

```bash
# Option A: Use TMI CLI to get token
tmi auth login

# Option B: Use OAuth flow via browser and extract token from browser storage
```

### 2. Create Webhook Subscription

```bash
# Get webhook URL from Terraform output
WEBHOOK_URL=$(terraform output -raw webhook_url)
WEBHOOK_SECRET="your-webhook-secret-from-secrets-manager"

# Create subscription
curl -X POST https://api.tmi.dev/api/v1/webhooks \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"TMI Terraform Analyzer (Lambda)\",
    \"url\": \"${WEBHOOK_URL}\",
    \"events\": [\"repository.created\", \"repository.updated\"],
    \"secret\": \"${WEBHOOK_SECRET}\",
    \"active\": true
  }"
```

### 3. Verify Challenge/Response

TMI will send a challenge request to verify the webhook endpoint:

```bash
# Check receiver Lambda logs
aws logs tail /aws/lambda/tmi-tf-dev-webhook-receiver --follow

# Look for:
# "Received challenge: xxx-yyy-zzz"
# "Returning challenge response"
```

TMI subscription status should change to `active` after successful verification.

---

## Verification

### 1. Manual Webhook Test

```bash
# Get webhook URL
WEBHOOK_URL=$(terraform output -raw webhook_url)

# Send test challenge
curl -X POST "${WEBHOOK_URL}" \
  -H "X-Webhook-Challenge: test-challenge-12345" \
  -H "Content-Type: application/json" \
  -d '{"type": "webhook.challenge", "challenge": "test-challenge-12345"}'

# Expected response: {"challenge": "test-challenge-12345"}
```

### 2. End-to-End Test

1. **Create test repository in TMI**:
   - Go to TMI UI → Threat Model → Add Repository
   - Enter a GitHub repository URL with Terraform files

2. **Monitor execution**:
   ```bash
   # Watch receiver Lambda logs
   aws logs tail /aws/lambda/tmi-tf-dev-webhook-receiver --follow

   # Watch analyzer Lambda logs (in another terminal)
   aws logs tail /aws/lambda/tmi-tf-dev-analyzer --follow

   # Check SQS queue
   aws sqs get-queue-attributes \
     --queue-url $(terraform output -raw sqs_queue_url) \
     --attribute-names ApproximateNumberOfMessages
   ```

3. **Verify note creation**:
   - Go to TMI UI → Threat Model → Notes
   - Look for "Terraform Analysis: [repository-name]"
   - Note should contain analysis results and webhook metadata

### 3. Check Metrics

```bash
# Receiver Lambda invocations
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=$(terraform output -raw receiver_lambda_name) \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum

# Analyzer Lambda invocations
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=$(terraform output -raw analyzer_lambda_name) \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

---

## Troubleshooting

### Webhook Returns 401 Unauthorized

**Cause**: HMAC signature mismatch

**Fix**:
```bash
# Verify webhook secret in Secrets Manager matches TMI subscription
aws secretsmanager get-secret-value \
  --secret-id $(terraform output -raw secrets_manager_arn) \
  --query SecretString --output text | jq -r '.webhook_secret'

# Compare with TMI webhook subscription secret
```

### Analysis Times Out

**Cause**: Repository too large or network issues

**Fix**:
```bash
# Increase Lambda timeout and /tmp storage
# Edit environments/prod.tfvars:
analyzer_lambda_timeout           = 1200  # 20 minutes
analyzer_lambda_ephemeral_storage = 5120  # 5GB

# Reapply Terraform
terraform apply -var-file=environments/prod.tfvars ...
```

### Messages in DLQ

**Cause**: Persistent failures (e.g., invalid repository, API errors)

**Fix**:
```bash
# Inspect DLQ messages
aws sqs receive-message \
  --queue-url $(terraform output -raw sqs_dlq_url) \
  --max-number-of-messages 10

# Check analyzer Lambda logs for error details
aws logs filter-log-events \
  --log-group-name $(terraform output -raw cloudwatch_log_group_analyzer) \
  --filter-pattern "ERROR"

# Re-drive messages after fixing issue
aws sqs start-message-move-task \
  --source-arn $(terraform output -raw sqs_dlq_arn) \
  --destination-arn $(terraform output -raw sqs_queue_arn)
```

### High Costs

**Cause**: Excessive analysis or large repositories

**Fix**:
```bash
# Check CloudWatch Logs Insights for top threat models
aws logs start-query \
  --log-group-name $(terraform output -raw cloudwatch_log_group_analyzer) \
  --start-time $(date -u -d '24 hours ago' +%s) \
  --end-time $(date -u +%s) \
  --query-string 'fields @timestamp, threat_model_id | stats count() by threat_model_id | sort count() desc | limit 10'

# Consider rate limiting or using Claude Haiku for simple repos
```

### Cannot Delete Stack

**Cause**: Lambda functions have ENIs in VPC

**Fix**:
```bash
# Wait for ENIs to be cleaned up (5-10 minutes)
# Or manually delete ENIs in EC2 console

# Then retry destroy
terraform destroy -var-file=environments/dev.tfvars ...
```

---

## Next Steps

1. **Set up monitoring dashboard**: See [README.md](README.md#monitoring) for CloudWatch dashboard configuration
2. **Configure alerts**: Set up PagerDuty/Slack integration with SNS topic
3. **Enable diagram generation**: Re-enable DFD generation in analyzer Lambda (requires additional dependencies)
4. **Multi-region deployment**: Deploy to us-west-2 for disaster recovery
5. **CI/CD pipeline**: Set up GitHub Actions for automated deployments

---

## Support

- **CloudWatch Logs**: Check receiver and analyzer Lambda logs
- **DLQ Messages**: Inspect SQS dead letter queue for failed messages
- **X-Ray Traces**: View distributed traces in AWS X-Ray console
- **Documentation**: See [README.md](README.md) for architecture details
- **Issues**: Report issues at GitHub repository
