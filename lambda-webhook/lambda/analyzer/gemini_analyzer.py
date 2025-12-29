"""
Google Gemini API analyzer for Terraform infrastructure via Vertex AI.

Uses Google Cloud Vertex AI for Gemini models with support for prompt caching
and multimodal capabilities.
"""
import json
import os
import tempfile
from typing import Dict, Any, List
from pathlib import Path
from google.oauth2 import service_account
import vertexai
from vertexai.generative_models import GenerativeModel, GenerationConfig


class GeminiAnalyzer:
    """Terraform analyzer using Google Gemini via Vertex AI"""

    # Vertex AI Gemini pricing (us-central1, as of December 2024)
    PRICING = {
        'gemini-2.0-flash-exp': {
            'input': 0.0,    # Free during preview
            'output': 0.0,   # Free during preview
            'cached_input': 0.0
        },
        'gemini-1.5-flash-002': {
            'input': 0.075,
            'output': 0.30,
            'cached_input': 0.01875  # 75% discount
        },
        'gemini-1.5-pro-002': {
            'input': 1.25,
            'output': 5.00,
            'cached_input': 0.3125  # 75% discount
        }
    }

    def __init__(self, config):
        """
        Initialize Gemini analyzer with Vertex AI.

        Args:
            config: LambdaConfig with gcp_service_account_key, gcp_project_id, gcp_location
        """
        self.config = config
        self.project_id = config.gcp_project_id
        self.location = getattr(config, 'gcp_location', 'us-central1')
        self.model_name = getattr(config, 'llm_model', 'gemini-2.0-flash-exp')

        # Initialize Vertex AI
        self._initialize_vertex_ai()

        # Initialize model
        self.model = GenerativeModel(
            self.model_name,
            system_instruction=[self._get_system_instruction()]
        )

    def _initialize_vertex_ai(self):
        """Initialize Vertex AI with service account credentials from Secrets Manager"""
        # Parse service account key (stored as JSON string in Secrets Manager)
        sa_key_dict = json.loads(self.config.gcp_service_account_key)

        # Write to temp file (Lambda /tmp)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sa_key_dict, f)
            sa_key_path = f.name

        try:
            # Create credentials
            credentials = service_account.Credentials.from_service_account_file(
                sa_key_path,
                scopes=['https://www.googleapis.com/auth/cloud-platform']
            )

            # Initialize Vertex AI
            vertexai.init(
                project=self.project_id,
                location=self.location,
                credentials=credentials
            )

        finally:
            # Clean up temp file
            if os.path.exists(sa_key_path):
                os.unlink(sa_key_path)

    def _get_system_instruction(self) -> str:
        """Get system instruction for Terraform security analysis"""
        return """You are an expert security-focused infrastructure analyst specializing in Terraform and cloud infrastructure.

Your expertise includes:
- Infrastructure as Code (IaC) security best practices
- Cloud security across AWS, Azure, GCP, and Kubernetes
- Compliance frameworks: CIS Benchmarks, NIST CSF, PCI-DSS, HIPAA, SOC2, ISO 27001
- Threat modeling and attack surface analysis
- Security misconfigurations and vulnerabilities
- Zero-trust architecture principles

Your task is to analyze Terraform configurations and identify:
1. Security vulnerabilities and misconfigurations
2. Infrastructure risks and potential attack vectors
3. Compliance violations and framework gaps
4. Access control and IAM permission issues
5. Data exposure and encryption risks
6. Network security weaknesses
7. Secrets and credential management problems
8. Resource exposure (public access, overly permissive policies)
9. Monitoring and logging gaps
10. Best practice violations

Provide thorough, actionable analysis in well-structured markdown format with specific code examples and remediation steps."""

    def analyze_repository(self, tf_repo) -> Dict[str, Any]:
        """
        Analyze Terraform repository using Gemini.

        Args:
            tf_repo: Repository object with path to cloned Terraform files

        Returns:
            Dictionary with analysis results, metadata, and cost
        """
        # Collect Terraform files
        tf_files = self._collect_terraform_files(tf_repo.path)

        if not tf_files:
            return {
                'analysis': '# No Terraform Files Found\n\nNo .tf files were found in this repository.',
                'model': self.model_name,
                'input_tokens': 0,
                'output_tokens': 0,
                'cached_tokens': 0,
                'total_cost': 0.0,
                'provider': 'gemini'
            }

        # Build analysis prompt
        user_prompt = self._build_analysis_prompt(tf_files)

        # Generation config
        generation_config = GenerationConfig(
            temperature=0.3,
            max_output_tokens=8192,
            top_p=0.95,
            top_k=40,
        )

        # Generate content
        response = self.model.generate_content(
            user_prompt,
            generation_config=generation_config
        )

        # Extract usage metadata
        usage = response.usage_metadata

        return {
            'analysis': response.text,
            'model': self.model_name,
            'input_tokens': usage.prompt_token_count,
            'output_tokens': usage.candidates_token_count,
            'cached_tokens': getattr(usage, 'cached_content_token_count', 0),
            'total_cost': self._calculate_cost(usage),
            'provider': 'gemini'
        }

    def _collect_terraform_files(self, repo_path: str) -> List[Dict[str, str]]:
        """Collect all .tf files from repository"""
        tf_files = []

        for tf_file in Path(repo_path).rglob("*.tf"):
            try:
                with open(tf_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if content.strip():  # Skip empty files
                        tf_files.append({
                            'path': str(tf_file.relative_to(repo_path)),
                            'content': content
                        })
            except Exception as e:
                print(f"Warning: Could not read {tf_file}: {e}")

        return tf_files

    def _build_analysis_prompt(self, tf_files: List[Dict[str, str]]) -> str:
        """Build comprehensive analysis prompt"""

        # Header
        prompt = f"""# Terraform Security Analysis Request

Analyze the following Terraform infrastructure configuration for security vulnerabilities,
misconfigurations, and compliance issues.

## Repository Contents

Found {len(tf_files)} Terraform file(s):

"""

        # Add each file
        for tf_file in tf_files:
            prompt += f"""
---
**File**: `{tf_file['path']}`

```hcl
{tf_file['content']}
```

"""

        # Analysis instructions
        prompt += """
---

## Analysis Requirements

Provide a comprehensive security analysis with the following structure:

### 1. Executive Summary
- Overall security posture assessment (2-3 paragraphs)
- Critical findings count and severity distribution
- Risk level classification (Critical/High/Medium/Low)
- Key recommendations summary

### 2. Security Findings

For each finding, provide:
- **Severity**: Critical / High / Medium / Low / Info
- **Title**: Brief, descriptive title
- **Description**: Detailed explanation of the issue and why it matters
- **Location**: Specific file(s) and resource(s) affected
- **Impact**: Potential security consequences, attack scenarios, blast radius
- **Remediation**: Step-by-step fix with complete code examples
- **References**: CIS benchmark rules, NIST controls, OWASP guidelines, relevant CVEs

Organize findings by severity (Critical first, then High, Medium, Low, Info).

### 3. Compliance Analysis
- **CIS Benchmarks**: Specific rule violations with numbers
- **NIST Cybersecurity Framework**: Control gaps (Identify, Protect, Detect, Respond, Recover)
- **Industry Standards**: PCI-DSS, HIPAA, SOC2, ISO 27001 requirements not met
- **Cloud Provider Best Practices**: AWS Well-Architected, Azure Security Benchmark, GCP Security Foundations

### 4. Architecture & Design Issues
- Infrastructure design flaws and anti-patterns
- Network segmentation and zone isolation problems
- Trust boundary violations
- Defense-in-depth gaps
- Single points of failure
- Scalability and resilience concerns

### 5. Access Control & IAM
- Overly permissive policies
- Missing least-privilege principles
- Service account and role issues
- MFA and authentication gaps
- Cross-account access risks

### 6. Data Security
- Encryption at rest and in transit
- Key management issues
- Backup and disaster recovery gaps
- Data retention and lifecycle policies
- PII and sensitive data handling

### 7. Network Security
- Public exposure risks
- Security group and firewall misconfigurations
- VPN and connectivity issues
- DNS security
- DDoS protection gaps

### 8. Monitoring & Logging
- CloudTrail/Cloud Audit log gaps
- Metric and alarm coverage
- SIEM integration requirements
- Incident response capabilities

### 9. Best Practices
- Terraform coding standards
- State management and backend security
- Module usage, versioning, and source control
- Documentation quality
- CI/CD integration recommendations
- Testing and validation strategies

### 10. Prioritized Recommendations

1. **Critical Actions** (Immediate - within 24 hours)
   - Security vulnerabilities requiring urgent fixes

2. **High Priority** (Short-term - within 1 week)
   - Significant risks and compliance gaps

3. **Medium Priority** (Medium-term - within 1 month)
   - Important improvements and quick wins

4. **Low Priority** (Long-term - within quarter)
   - Strategic improvements and optimizations

For each recommendation, include:
- Specific action items
- Estimated effort (hours/days)
- Required resources or expertise
- Dependencies

---

**Output Format**: Use clear, well-structured markdown with:
- Proper headers (##, ###, ####)
- Bulleted and numbered lists
- Code blocks with syntax highlighting
- Tables where appropriate
- Emphasis (**bold**, *italic*) for key points

Focus on actionable, specific guidance that developers can implement immediately.
Prioritize findings based on real-world impact and exploitability.
"""

        return prompt

    def _calculate_cost(self, usage) -> float:
        """
        Calculate cost based on Vertex AI Gemini pricing.

        Args:
            usage: Vertex AI usage metadata object

        Returns:
            Total cost in USD
        """
        pricing = self.PRICING.get(self.model_name, self.PRICING['gemini-1.5-flash-002'])

        input_tokens = usage.prompt_token_count
        output_tokens = usage.candidates_token_count
        cached_tokens = getattr(usage, 'cached_content_token_count', 0)

        # Calculate costs
        regular_input_tokens = max(0, input_tokens - cached_tokens)
        input_cost = (regular_input_tokens / 1_000_000) * pricing['input']
        cached_cost = (cached_tokens / 1_000_000) * pricing['cached_input']
        output_cost = (output_tokens / 1_000_000) * pricing['output']

        return input_cost + cached_cost + output_cost
