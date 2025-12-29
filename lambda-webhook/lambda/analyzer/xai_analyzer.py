"""
x.ai Grok API analyzer for Terraform infrastructure.

Uses the OpenAI-compatible API provided by x.ai for Grok models.
"""
from typing import Dict, Any, List
from pathlib import Path
from openai import OpenAI


class XaiAnalyzer:
    """Terraform analyzer using x.ai Grok API"""

    # x.ai pricing (as of December 2024)
    PRICING = {
        'grok-beta': {
            'input': 5.0,   # $ per million tokens
            'output': 15.0  # $ per million tokens
        },
        'grok-vision-beta': {
            'input': 5.0,
            'output': 15.0
        }
    }

    def __init__(self, config):
        """
        Initialize x.ai Grok analyzer.

        Args:
            config: LambdaConfig with xai_api_key
        """
        self.config = config
        self.model = getattr(config, 'llm_model', 'grok-beta')

        # Initialize OpenAI client with x.ai endpoint
        self.client = OpenAI(
            api_key=config.xai_api_key,
            base_url="https://api.x.ai/v1"
        )

    def analyze_repository(self, tf_repo) -> Dict[str, Any]:
        """
        Analyze Terraform repository using Grok.

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
                'model': self.model,
                'input_tokens': 0,
                'output_tokens': 0,
                'total_cost': 0.0,
                'provider': 'xai'
            }

        # Build analysis prompt
        user_prompt = self._build_analysis_prompt(tf_files)

        # Call Grok API
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": self._get_system_instruction()
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ],
            temperature=0.3,
            max_tokens=8000,
            stream=False
        )

        # Extract response
        analysis_text = response.choices[0].message.content
        usage = response.usage

        return {
            'analysis': analysis_text,
            'model': self.model,
            'input_tokens': usage.prompt_tokens,
            'output_tokens': usage.completion_tokens,
            'total_cost': self._calculate_cost(usage),
            'provider': 'xai'
        }

    def _get_system_instruction(self) -> str:
        """Get system instruction for Terraform security analysis"""
        return """You are an expert security-focused infrastructure analyst specializing in Terraform and cloud infrastructure.

Your expertise includes:
- Infrastructure as Code (IaC) security best practices
- Cloud security (AWS, Azure, GCP, Kubernetes)
- Compliance frameworks (CIS, NIST, PCI-DSS, HIPAA, SOC2)
- Threat modeling and attack surface analysis
- Security misconfigurations and vulnerabilities

Your task is to analyze Terraform configurations and identify:
1. Security vulnerabilities and misconfigurations
2. Infrastructure risks and potential attack vectors
3. Compliance violations and framework gaps
4. Access control and permission issues
5. Data exposure risks
6. Network security weaknesses
7. Secrets management problems
8. Best practice violations

Provide thorough, actionable analysis in well-structured markdown format."""

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
- Overall security posture assessment
- Critical findings count and severity distribution
- Risk level classification (Critical/High/Medium/Low)
- Key recommendations summary

### 2. Security Findings

For each finding, provide:
- **Severity**: Critical / High / Medium / Low / Info
- **Title**: Brief, descriptive title
- **Description**: Detailed explanation of the issue
- **Location**: Specific file(s) and resource(s) affected
- **Impact**: Potential security consequences and attack scenarios
- **Remediation**: Step-by-step fix with code examples
- **References**: CIS benchmarks, NIST controls, OWASP guidelines, CVEs

Organize findings by severity (Critical first, then High, Medium, Low, Info).

### 3. Compliance Analysis
- CIS Benchmark violations (specific rule numbers)
- NIST Cybersecurity Framework gaps
- Industry-specific compliance issues (PCI-DSS, HIPAA, SOC2, ISO 27001)
- Regulatory requirements not met

### 4. Architecture & Design Issues
- Infrastructure design flaws
- Network segmentation problems
- Trust boundary violations
- Defense-in-depth gaps

### 5. Best Practices
- Terraform coding standards
- State management and backend security
- Module usage and versioning
- Documentation quality
- CI/CD integration recommendations

### 6. Prioritized Recommendations
1. **Immediate Actions** (Critical/High severity)
2. **Short-term Improvements** (Medium severity, quick wins)
3. **Long-term Strategic Changes** (Architecture improvements)

Use clear, well-structured markdown with proper headers, lists, and code blocks.
Focus on actionable, specific guidance that developers can implement immediately.
"""

        return prompt

    def _calculate_cost(self, usage) -> float:
        """
        Calculate cost based on x.ai pricing.

        Args:
            usage: OpenAI usage object with prompt_tokens and completion_tokens

        Returns:
            Total cost in USD
        """
        pricing = self.PRICING.get(self.model, self.PRICING['grok-beta'])

        input_cost = (usage.prompt_tokens / 1_000_000) * pricing['input']
        output_cost = (usage.completion_tokens / 1_000_000) * pricing['output']

        return input_cost + output_cost
