# TMI Terraform Analysis Tool

Automated Terraform infrastructure analysis tool for threat modeling using Claude AI.

## Overview

The TMI Terraform Analysis Tool automates the analysis of Terraform infrastructure code associated with threat models in the TMI (Threat Modeling Improved) platform. It uses Claude Sonnet 4.5 to analyze infrastructure components, relationships, data flows, and security considerations, then generates comprehensive markdown reports stored as notes in TMI.

## Features

- **OAuth Authentication**: Seamless integration with TMI server using Google Sign-In
- **Smart Repository Discovery**: Automatically identifies GitHub repositories with Terraform code from threat models
- **Sparse Cloning**: Efficiently clones only Terraform and documentation files
- **AI-Powered Analysis**: Leverages Claude Sonnet 4.5 to analyze infrastructure security
- **Visual Diagrams**: Generates mermaid diagrams showing architecture and data flows
- **Comprehensive Reports**: Creates detailed markdown reports with security observations
- **TMI Integration**: Stores analysis results as notes in threat models for easy collaboration

## Prerequisites

- Python 3.10 or higher
- [UV](https://github.com/astral-sh/uv) package manager
- Git
- Access to a TMI server (https://api.tmi.dev)
- Anthropic API key (for Claude)
- Optional: GitHub personal access token (for higher API rate limits)

## Installation

1. Clone this repository:
```bash
cd ~/Projects
git clone <repository-url> tmi-tf
cd tmi-tf
```

2. Copy the example environment file and configure it:
```bash
cp .env.example .env
```

3. Edit `.env` and set your API keys:
```bash
ANTHROPIC_API_KEY=your_actual_anthropic_api_key_here
GITHUB_TOKEN=your_github_token_here  # Optional
```

4. Install dependencies using UV:
```bash
uv sync
```

## Configuration

All configuration is managed through the `.env` file:

| Variable | Description | Default |
|----------|-------------|---------|
| `TMI_SERVER_URL` | TMI server URL | `https://api.tmi.dev` |
| `TMI_OAUTH_IDP` | OAuth identity provider | `google` |
| `ANTHROPIC_API_KEY` | Claude API key | *Required* |
| `GITHUB_TOKEN` | GitHub personal access token | *Optional* |
| `MAX_REPOS` | Maximum repositories to analyze | `3` |
| `CLONE_TIMEOUT` | Git clone timeout in seconds | `300` |
| `ANALYSIS_NOTE_NAME` | Name for the generated note | `Terraform Analysis Report` |

## Usage

### Basic Commands

View configuration:
```bash
uv run tmi-tf config-info
```

Authenticate with TMI server:
```bash
uv run tmi-tf auth
```

List repositories in a threat model:
```bash
uv run tmi-tf list-repos <threat-model-id>
```

Analyze Terraform repositories:
```bash
uv run tmi-tf analyze <threat-model-id>
```

### Analysis Options

```bash
uv run tmi-tf analyze <threat-model-id> [OPTIONS]
```

Options:
- `--max-repos INTEGER`: Override maximum number of repositories to analyze
- `--dry-run`: Analyze but don't create note (output to stdout)
- `--output PATH`: Save markdown report to file
- `--force-auth`: Force new authentication (ignore cached token)
- `--verbose`: Enable verbose logging

### Examples

Analyze a threat model and save results to TMI:
```bash
uv run tmi-tf analyze abc-123-def-456
```

Analyze with custom output file:
```bash
uv run tmi-tf analyze abc-123-def-456 --output report.md
```

Dry run to preview analysis without creating note:
```bash
uv run tmi-tf analyze abc-123-def-456 --dry-run
```

Analyze only 1 repository with verbose logging:
```bash
uv run tmi-tf analyze abc-123-def-456 --max-repos 1 --verbose
```

## How It Works

1. **Authentication**: Authenticates with TMI server using Google OAuth 2.0
2. **Discovery**: Fetches the specified threat model and its associated repositories
3. **Filtering**: Identifies GitHub repositories (up to MAX_REPOS)
4. **Cloning**: Sparse clones each repository (only .tf, .tfvars, and documentation files)
5. **Analysis**: Sends Terraform code to Claude for security analysis
6. **Report Generation**: Aggregates findings into a comprehensive markdown report
7. **Storage**: Creates or updates a note in the TMI threat model

## Project Structure

```
tmi-tf/
├── tmi_tf/
│   ├── __init__.py
│   ├── cli.py                  # CLI interface
│   ├── config.py               # Configuration management
│   ├── auth.py                 # OAuth authentication
│   ├── tmi_client_wrapper.py  # TMI API client
│   ├── github_client.py        # GitHub API integration
│   ├── repo_analyzer.py        # Repository cloning and extraction
│   ├── claude_analyzer.py      # Claude AI integration
│   └── markdown_generator.py   # Report generation
├── prompts/
│   ├── terraform_analysis_system.txt  # System prompt for Claude
│   └── terraform_analysis_user.txt    # User prompt template
├── .env                        # Environment configuration (not in git)
├── .env.example                # Example environment file
├── pyproject.toml              # Project dependencies
└── README.md                   # This file
```

## Analysis Output

The generated markdown report includes:

1. **Executive Summary**: Overview of analyzed repositories
2. **Per-Repository Analysis**:
   - Infrastructure inventory (compute, storage, network, security)
   - Component relationships and dependencies
   - Data flow mapping
   - Security observations and concerns
   - Architecture summary
   - Mermaid diagram of infrastructure
3. **Consolidated Findings**: Cross-repository insights and threat modeling recommendations

## Customization

### Modifying Analysis Prompts

Edit the prompt templates in the `prompts/` directory:
- `terraform_analysis_system.txt`: System-level instructions for Claude
- `terraform_analysis_user.txt`: Per-repository analysis request template

### Adjusting Analysis Scope

Modify sparse checkout patterns in `repo_analyzer.py` to include/exclude file types:
```python
patterns = [
    "*.tf",
    "*.tfvars",
    "*.md",
    # Add more patterns as needed
]
```

## Troubleshooting

### Authentication Issues

Clear cached token and re-authenticate:
```bash
uv run tmi-tf clear-auth
uv run tmi-tf auth
```

### Rate Limits

**GitHub API**:
- Unauthenticated: 60 requests/hour
- Authenticated: 5000 requests/hour
- Solution: Set `GITHUB_TOKEN` in `.env`

**Claude API**:
- Check your Anthropic account limits
- Tool will retry with exponential backoff

### Clone Timeouts

Increase timeout in `.env`:
```
CLONE_TIMEOUT=600
```

### Large Repositories

Tool automatically limits to MAX_REPOS. For very large .tf files, Claude may truncate analysis.

## Limitations & Considerations

- **Proof of Concept**: This is a PoC tool, not production-ready
- **Token Limits**: Claude has ~200K token context window; very large files may be truncated
- **GitHub Only**: Currently only supports GitHub repositories
- **Public Repos**: Best suited for public repositories (private repos require GitHub authentication)
- **Sequential Processing**: Repositories are analyzed sequentially (not parallelized)
- **No State Management**: No resume capability if analysis fails mid-way

## Security Considerations

- **API Keys**: Never commit `.env` file - it contains sensitive credentials
- **Token Cache**: OAuth tokens are cached in `~/.tmi-tf/token.json`
- **Temporary Files**: Cloned repositories are stored in temp directories and cleaned up automatically
- **Network Security**: All API calls use HTTPS

## Contributing

This is a proof-of-concept tool. Potential improvements:
- Support for other Git providers (GitLab, Bitbucket)
- Parallel repository processing
- Resume capability for long-running analyses
- Terraform state file analysis
- Integration with terraform security scanners (tfsec, checkov)
- Custom analysis rules and filters

## License

Apache License 2.0 - See LICENSE file

## Support

For issues and questions:
- Check logs with `--verbose` flag
- Review configuration with `config-info` command
- Ensure all prerequisites are installed
- Verify TMI server accessibility

---

**Version**: 0.1.0
**Status**: Proof of Concept
