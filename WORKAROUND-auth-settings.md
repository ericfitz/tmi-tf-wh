# TMI API Client Authentication Workaround

## Problem

The generated TMI Python API client (from OpenAPI spec) has an issue with Bearer token authentication. The `Configuration` class has an empty `auth_settings()` method, which prevents the API client from properly sending the `Authorization` header with Bearer tokens.

### Expected Behavior
When a Bearer token is configured via:
```python
config.api_key["bearerAuth"] = token
config.api_key_prefix["bearerAuth"] = "Bearer"
```

The API client should automatically include the Authorization header in requests:
```
Authorization: Bearer <token>
```

### Actual Behavior
The `auth_settings()` method returns an empty dict `{}`, so the API client doesn't know how to construct the Authorization header. All authenticated requests return `401 Unauthorized` even with a valid OAuth token.

## Root Cause

The OpenAPI generator creates a `Configuration.auth_settings()` method that should return authentication configuration, but in the generated code it's empty:

```python
def auth_settings(self):
    """Gets Auth Settings dict for api client.
    :return: The Auth Settings information dict.
    """
    return {}  # Empty - should return bearerAuth configuration
```

## Workaround

We're monkey-patching the `auth_settings()` method on the Configuration instance to properly return the Bearer token configuration:

```python
# In tmi_tf/tmi_client_wrapper.py

def auth_settings_override(self):
    return {
        'bearerAuth': {
            'type': 'api_key',
            'in': 'header',
            'key': 'Authorization',
            'value': self.get_api_key_with_prefix('bearerAuth')
        }
    }

# Bind the override method to the configuration instance
tmi_config.auth_settings = auth_settings_override.__get__(tmi_config, Configuration)
```

This workaround has been implemented in `tmi_tf/tmi_client_wrapper.py:93-106`.

## Recommended Fix

The proper fix should be made in the Python client generation process. The `Configuration.auth_settings()` method should be updated to return:

```python
def auth_settings(self):
    """Gets Auth Settings dict for api client.
    :return: The Auth Settings information dict.
    """
    auth = {}
    if 'bearerAuth' in self.api_key:
        auth['bearerAuth'] = {
            'type': 'api_key',
            'in': 'header',
            'key': 'Authorization',
            'value': self.get_api_key_with_prefix('bearerAuth')
        }
    return auth
```

## Impact

- **Severity**: High - Prevents all authenticated API access
- **Scope**: Affects all users of the Python client using Bearer token authentication
- **Temporary Solution**: Monkey-patch workaround (functional but not ideal)
- **Permanent Solution**: Fix in client generation/OpenAPI spec

## References

- Workaround implementation: `tmi_tf/tmi_client_wrapper.py:93-106`
- Related commit: `c052eeb` - "fix: restore auth_settings workaround for TMI API authentication"
