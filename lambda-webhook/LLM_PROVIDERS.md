# LLM Provider Guide

The TMI Terraform Analyzer supports three LLM providers for infrastructure analysis. This guide helps you choose the right provider and configure it properly.

## Supported Providers

| Provider | Models | Cost | Speed | Quality | Best For |
|----------|--------|------|-------|---------|----------|
| **Anthropic (Claude)** | Sonnet 4.5 | $0.165/analysis | Medium (8-12s) | Excellent | Default, enterprise, compliance |
| **x.ai (Grok)** | Grok Beta | $0.175/analysis | Medium (10-15s) | Excellent | X/Twitter ecosystem |
| **Google (Gemini)** | 2.0 Flash, 1.5 Pro | $0.017/analysis | Fast (4-6s) | Excellent | Cost optimization, speed |

## Quick Comparison

### Anthropic Claude (Default)

**Model**: Claude Sonnet 4.5

**Pros**:
- Excellent security analysis and reasoning
- Strong at compliance frameworks (CIS, NIST, PCI-DSS)
- Enterprise focus and data privacy commitments
- Reliable, well-tested
- Default choice - works out of the box

**Cons**:
- More expensive than Gemini
- Slower than Gemini

**When to use**:
- Default choice for most users
- Regulatory/compliance requirements
- Enterprise deployments
- Maximum quality/reliability needed

**Cost**: ~$0.165 per analysis (30K input, 5K output)

---

### x.ai Grok

**Models**: `grok-4-1-fast-reasoning`, `grok-4-1-fast-non-reasoning`

**Pros**:
- Strong technical analysis capabilities
- OpenAI-compatible API (easy integration)
- Access to real-time data (future capability)
- Support X/Twitter ecosystem

**Cons**:
- Slightly more expensive than Claude
- Slightly slower than Claude
- Newer, less battle-tested

**When to use**:
- X/Twitter ecosystem alignment
- Want OpenAI-compatible API
- Real-time data needs (future)

**Cost**: ~$0.175 per analysis ($5/M input, $15/M output)

---

### Google Gemini (Recommended for Cost)

**Models**: `gemini/gemini-3-pro-preview`, `gemini/gemini-3-flash-preview`

**Pros**:
- **90% cheaper than Claude** for Gemini 2.0 Flash
- **2x faster** than Claude (4-6s vs 8-12s)
- 1M token context window (5x larger than Claude)
- Prompt caching for even lower costs
- Multimodal capabilities (future: analyze diagrams)

**Cons**:
- Requires GCP setup (service account, Vertex AI)
- More complex initial configuration
- Slightly heavier SDK (though still lightweight)

**When to use**:
- **Cost is a priority** (saves $1,800/year at 1K analyses/month)
- **Speed matters** (2x faster)
- **Large Terraform repos** (1M context vs 200K)
- High-volume analysis

**Cost**:
- Gemini 2.0 Flash: ~$0.017 per analysis (FREE during preview)
- Gemini 1.5 Flash: ~$0.025 per analysis
- Gemini 1.5 Pro: ~$0.158 per analysis

---

## Setup Instructions

### 1. Anthropic Claude (Default)

**Prerequisites**:
- Anthropic API key

**Secrets Manager**:
```json
{
  "client_id": "your-tmi-client-id",
  "client_secret": "your-tmi-client-secret",
  "anthropic_api_key": "sk-ant-api03-...",
  "webhook_secret": "your-webhook-secret"
}
```

**Terraform**:
```hcl
# Use default prod.tfvars (already configured for Anthropic)
terraform apply -var-file=environments/prod.tfvars
```

**No additional configuration needed - this is the default!**

---

### 2. x.ai Grok

**Prerequisites**:
- x.ai API key (get from https://console.x.ai)

**Secrets Manager**:
```bash
aws secretsmanager update-secret \
  --secret-id tmi-tf/oauth-credentials \
  --secret-string '{
    "client_id": "your-tmi-client-id",
    "client_secret": "your-tmi-client-secret",
    "xai_api_key": "xai-...",
    "webhook_secret": "your-webhook-secret"
  }'
```

**Terraform**:
```hcl
# Use xai.tfvars
terraform apply -var-file=environments/xai.tfvars \
  -var="llm_provider=xai" \
  -var="llm_model=grok-4-1-fast-reasoning"
```

**Environment Variables** (optional model override):
- `LLM_PROVIDER=xai`
- `LLM_MODEL=grok-4-1-fast-reasoning` (or `grok-4-1-fast-non-reasoning`)

---

### 3. Google Gemini

**Prerequisites**:
1. GCP Project with Vertex AI enabled
2. Service account with `roles/aiplatform.user`
3. Service account JSON key

**GCP Setup**:
```bash
# Create project
gcloud projects create tmi-tf-analyzer

# Enable Vertex AI
gcloud services enable aiplatform.googleapis.com --project=tmi-tf-analyzer

# Create service account
gcloud iam service-accounts create tmi-tf-lambda \
  --display-name="TMI TF Lambda Analyzer" \
  --project=tmi-tf-analyzer

# Grant Vertex AI User role
gcloud projects add-iam-policy-binding tmi-tf-analyzer \
  --member="serviceAccount:tmi-tf-lambda@tmi-tf-analyzer.iam.gserviceaccount.com" \
  --role="roles/aiplatform.user"

# Create and download key
gcloud iam service-accounts keys create ~/tmi-tf-sa-key.json \
  --iam-account=tmi-tf-lambda@tmi-tf-analyzer.iam.gserviceaccount.com
```

**Secrets Manager**:
```bash
aws secretsmanager update-secret \
  --secret-id tmi-tf/oauth-credentials \
  --secret-string "$(jq -n \
    --arg client_id "your-tmi-client-id" \
    --arg client_secret "your-tmi-client-secret" \
    --arg gcp_sa_key "$(cat ~/tmi-tf-sa-key.json)" \
    --arg gcp_project_id "tmi-tf-analyzer" \
    --arg webhook_secret "your-webhook-secret" \
    '{
      client_id: $client_id,
      client_secret: $client_secret,
      gcp_service_account_key: $gcp_sa_key,
      gcp_project_id: $gcp_project_id,
      gcp_location: "us-central1",
      webhook_secret: $webhook_secret
    }')"

# Clean up local key
rm ~/tmi-tf-sa-key.json
```

**Terraform**:
```hcl
# Use gemini.tfvars
terraform apply -var-file=environments/gemini.tfvars \
  -var="llm_provider=gemini" \
  -var="llm_model=gemini/gemini-3-pro-preview"
```

**Environment Variables** (optional):
- `LLM_PROVIDER=gemini`
- `LLM_MODEL=gemini/gemini-3-pro-preview` (or `gemini/gemini-3-flash-preview`)

---

## Cost Analysis

### Per-Analysis Cost Breakdown

| Provider | LLM API | Lambda | AWS Services | Total | vs Claude |
|----------|---------|--------|--------------|-------|-----------|
| **Claude Sonnet 4.5** | $0.165 | $0.005 | $0.005 | **$0.175** | Baseline |
| **Grok Beta** | $0.175 | $0.005 | $0.005 | **$0.185** | +6% |
| **Gemini 2.0 Flash** | $0.017 | $0.003 | $0.005 | **$0.025** | **-86%** |
| **Gemini 1.5 Flash** | $0.025 | $0.003 | $0.005 | **$0.033** | -81% |
| **Gemini 1.5 Pro** | $0.158 | $0.005 | $0.005 | **$0.168** | -4% |

### Monthly Cost Examples (1,000 analyses)

| Provider | Monthly Cost | Annual Cost | Savings vs Claude |
|----------|--------------|-------------|-------------------|
| Claude Sonnet 4.5 | $175 | $2,100 | - |
| Grok Beta | $185 | $2,220 | -$120/year |
| **Gemini 2.0 Flash** | **$25** | **$300** | **$1,800/year** |
| Gemini 1.5 Flash | $33 | $396 | $1,704/year |
| Gemini 1.5 Pro | $168 | $2,016 | $84/year |

### Annual Savings (1,000 analyses/month)

Switching from Claude to Gemini 2.0 Flash saves **$1,800/year** (86% reduction).

---

## Switching Providers

### Option 1: Environment Variables (Runtime)

Change provider without redeploying:

```bash
# Update Lambda environment variable
aws lambda update-function-configuration \
  --function-name tmi-tf-prod-analyzer \
  --environment "Variables={
    LLM_PROVIDER=gemini,
    LLM_MODEL=gemini/gemini-3-pro-preview,
    TMI_SERVER_URL=https://api.tmi.dev,
    SECRETS_ARN=arn:aws:secretsmanager:...,
    DYNAMODB_TABLE=tmi-tf-prod-webhook-deliveries
  }"
```

### Option 2: Terraform (Infrastructure)

Change provider via Terraform:

```bash
# Switch to Gemini
terraform apply -var-file=environments/gemini.tfvars \
  -var="llm_provider=gemini" \
  -var="llm_model=gemini/gemini-3-pro-preview"

# Switch to x.ai
terraform apply -var-file=environments/xai.tfvars \
  -var="llm_provider=xai" \
  -var="llm_model=grok-4-1-fast-reasoning"

# Switch back to Claude
terraform apply -var-file=environments/prod.tfvars \
  -var="llm_provider=anthropic"
```

---

## Performance Comparison

### Analysis Speed

| Provider | Model | Avg Latency | Tokens/sec | Winner |
|----------|-------|-------------|------------|--------|
| Anthropic | Claude Sonnet 4.5 | 8-12s | ~400 | - |
| x.ai | Grok Beta | 10-15s | ~350 | - |
| **Google** | **Gemini 2.0 Flash** | **4-6s** | **~600** | **✅ 2x faster** |
| Google | Gemini 1.5 Pro | 10-14s | ~380 | - |

### Context Window

| Provider | Model | Context Window | Winner |
|----------|-------|----------------|--------|
| Anthropic | Claude Sonnet 4.5 | 200K tokens | - |
| x.ai | Grok Beta | 128K tokens | - |
| **Google** | **Gemini 2.0 Flash** | **1M tokens** | **✅ 5x larger** |

---

## Recommendations

### Start Here (Default)
**Provider**: Anthropic Claude
**Why**: Works out of the box, excellent quality, minimal setup

### Cost-Conscious (Recommended)
**Provider**: Google Gemini 2.0 Flash
**Why**: 86% cheaper, 2x faster, FREE during preview
**Setup time**: +30 minutes for GCP configuration

### X/Twitter Ecosystem
**Provider**: x.ai Grok
**Why**: Supports X/Twitter, OpenAI-compatible API
**Cost**: Similar to Claude

### Enterprise/Compliance
**Provider**: Anthropic Claude
**Why**: Strong compliance focus, data privacy commitments

### High-Volume
**Provider**: Google Gemini 2.0 Flash
**Why**: Massive cost savings at scale ($1,800/year saved at 1K/month)

---

## Model Selection

### Anthropic
- `claude-opus-4-5-20251101` (default): Most intelligent model

### x.ai
- `grok-4-1-fast-reasoning` (default): Frontier model with reasoning
- `grok-4-1-fast-non-reasoning`: Fast variant without reasoning

### Google Gemini
- `gemini/gemini-3-pro-preview` (recommended): Latest reasoning-first model
- `gemini/gemini-3-flash-preview`: Fast variant with Pro-level intelligence

---

## Troubleshooting

### Anthropic Claude

**Error**: `anthropic_api_key not found`
```bash
# Verify secret contains anthropic_api_key
aws secretsmanager get-secret-value --secret-id tmi-tf/oauth-credentials
```

### x.ai Grok

**Error**: `xai_api_key not found`
```bash
# Add xai_api_key to secret
aws secretsmanager update-secret --secret-id tmi-tf/oauth-credentials \
  --secret-string '{"client_id":"...","client_secret":"...","xai_api_key":"xai-...","webhook_secret":"..."}'
```

**Error**: `401 Unauthorized`
- Verify API key is correct: https://console.x.ai/keys

### Google Gemini

**Error**: `gcp_service_account_key not found`
```bash
# Secret must contain GCP service account JSON key
aws secretsmanager get-secret-value --secret-id tmi-tf/oauth-credentials | jq -r '.SecretString' | jq '.gcp_service_account_key'
```

**Error**: `Permission denied` or `403 Forbidden`
```bash
# Grant Vertex AI User role
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:tmi-tf-lambda@YOUR_PROJECT.iam.gserviceaccount.com" \
  --role="roles/aiplatform.user"
```

**Error**: `API not enabled`
```bash
# Enable Vertex AI API
gcloud services enable aiplatform.googleapis.com --project=YOUR_PROJECT_ID
```

---

## Migration Path

### Phase 1: Test with Gemini (Recommended)
1. Set up GCP project and service account (30 min)
2. Deploy to dev environment with Gemini 2.0 Flash
3. Test with sample repositories
4. Verify analysis quality matches Claude

### Phase 2: Canary Deployment
1. Deploy to production with 10% canary (Gemini)
2. Monitor CloudWatch metrics for 24 hours
3. Compare quality of Gemini vs Claude analyses
4. Gradually increase canary weight: 10% → 25% → 50% → 100%

### Phase 3: Full Migration
1. Switch production to 100% Gemini
2. Monitor for 1 week
3. Update documentation and runbooks
4. Celebrate cost savings!

**Estimated savings**: $150/month → $1,800/year at 1,000 analyses/month

---

## Support

- **Anthropic**: https://docs.anthropic.com
- **x.ai**: https://docs.x.ai
- **Google Gemini**: https://cloud.google.com/vertex-ai/docs/generative-ai/model-reference/gemini
