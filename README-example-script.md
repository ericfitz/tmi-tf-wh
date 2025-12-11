# Example Threat Model Creation Script

This document explains how to use the [create_and_analyze_example_cli.py](create_and_analyze_example_cli.py) script to create an example threat model and run tmi-tf analysis on it.

## What the Script Does

The script performs the following steps:

1. **Creates a threat model** named "Example: AI Automated Terraform Template Analysis" with a description explaining that it's an AI-generated analysis
2. **Adds a GitHub repository** containing Terraform templates (oracle-devrel/terraform-oci-arch-web-ha) to the threat model
3. **Runs the tmi_tf analyze command** against the threat model to generate security analysis

## Prerequisites

- Python 3.10 or higher
- UV package manager installed
- TMI authentication configured (run `uv run python -m tmi_tf.cli auth` first)
- ANTHROPIC_API_KEY configured in `.env` file

## Usage

```bash
# Make sure you're in the tmi-tf directory
cd /Users/efitz/Projects/tmi-tf

# First, authenticate with TMI (if not already done)
uv run python -m tmi_tf.cli auth

# Run the script
uv run python create_and_analyze_example_cli.py
```

## Script Output

The script will:
- Load your cached TMI authentication token
- Create a new threat model via the TMI API
- Add the specified Git repository to the threat model
- Run the tmi_tf analyze command to generate:
  - Security analysis notes
  - Infrastructure data flow diagram
  - Identified threats

## Known Issues

### Generated Client Library Issues

There are currently two known issues with the auto-generated TMI Python client library:

1. **Empty `auth_settings()` method**: The generated client's `Configuration.auth_settings()` method returns an empty dictionary, preventing proper Bearer token authentication.
   - **Fix Applied**: The [tmi_client_wrapper.py](tmi_tf/tmi_client_wrapper.py) now includes a monkey-patch that overrides the `auth_settings()` method to properly configure Bearer authentication.

2. **Missing `principal_type` field validation**: The generated client models expect a `principal_type` field on User objects, but the API may return users without this field set.
   - **Workaround**: Use direct API calls via the `requests` library for threat model creation (as this script does), and use the tmi_tf CLI for analysis.

### Current Limitations

- The `tmi_tf analyze` command may fail with model validation errors due to issue #2 above
- However, the threat model and repository are successfully created and can be viewed in the TMI web interface

## Alternative Approach

If the analyze command fails, you can:

1. Use the script to create the threat model and repository
2. Note the Threat Model ID from the output
3. Run the analysis manually using the TMI web interface, or
4. Wait for fixes to the generated client library

## Example Output

```
🚀 Starting Example Threat Model Creation and Analysis
================================================================================
🔐 Loading authentication token...
✅ Token loaded
📝 Creating threat model...
✅ Created threat model with ID: 1395c999-2e25-4adc-971d-6f92d373f255
   Name: Example: AI Automated Terraform Template Analysis

📦 Adding repository to threat model...
✅ Added repository: https://github.com/oracle-devrel/terraform-oci-arch-web-ha.git
   Repository ID: 245c2f4e-35e7-4a50-95ad-630ad490aae3

🔍 Running tmi_tf analysis on threat model 1395c999-2e25-4adc-971d-6f92d373f255...
================================================================================
...
```

## Files

- **create_and_analyze_example_cli.py**: Main script that creates threat model and runs analysis
- **create_and_analyze_example.py**: Earlier version that uses TMI client library directly (has authentication issues)
- **README-example-script.md**: This documentation file

## Customization

You can modify the script to:

- Change the threat model name and description
- Add different repositories
- Specify different branch names (change `refValue` in the parameters)
- Add multiple repositories in a loop
- Customize the analyze command flags

## API Reference

The script uses the following TMI API endpoints:

- `POST /threat_models` - Create a new threat model
- `POST /threat_models/{id}/repositories` - Add a repository to a threat model

Repository parameters must include:
- `refType`: One of "branch", "tag", or "commit"
- `refValue`: The name/value of the branch, tag, or commit SHA

## Support

For issues with:
- **TMI API**: Refer to the TMI API documentation
- **tmi-tf tool**: See https://github.com/ericfitz/tmi-tf
- **Generated client bugs**: Consider regenerating the client from the updated OpenAPI spec

