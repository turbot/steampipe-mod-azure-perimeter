# Resource Policy Public Access

## Overview

Resources can be exposed to public access through resource policies, access policies, or authorization rules that grant permissions to unauthorized users or overly broad access patterns. Unlike configuration-based public access settings, policy-based access uses explicit access control statements that can be misconfigured to allow public access.

Azure services that use policy-based access control include:

- **Azure Key Vault** - Access policies that define which principals can access keys, secrets, and certificates
- **Azure Service Bus** - Shared access policies (authorization rules) that grant specific rights to send, listen, or manage
- **Azure Storage** - Cross-Origin Resource Sharing (CORS) policies and network access rules
- **Azure Cosmos DB** - CORS policies that control cross-origin access
- **Azure SQL Server** - Firewall rules that control network access

## Security Concerns

Policy-based public access can be particularly dangerous because:

1. **Granular Permissions**: Policies can grant specific permissions that may not be immediately obvious
2. **Multiple Access Paths**: Multiple policies can exist, creating complex access patterns
3. **Credential Exposure**: Policy-based access often uses connection strings or access keys that can be exposed
4. **Bypass Controls**: These policies can bypass other access controls like network restrictions

## Common Misconfigurations

### Key Vault Access Policies
- Granting access to wildcard principals (`*`)
- Using placeholder or default object IDs (`00000000-0000-0000-0000-000000000000`) 
- Granting wildcard permissions for secrets, keys, or certificates (`*`)

### Service Bus Authorization Rules
- Creating non-default shared access policies with Manage rights
- Creating policies with both Listen and Send rights outside of default configurations
- Using shared access signatures derived from overly permissive policies

### Storage Account CORS Policies
- Allowing access from any origin (`*`) in CORS policies
- Overly permissive CORS configurations that expose data to any website

### Cosmos DB CORS Policies  
- Configuring CORS to allow requests from any origin (`*`)
- Broad CORS policies that could expose database contents

### SQL Server Firewall Rules
- Rules allowing access from any IP address (0.0.0.0 to 255.255.255.255)
- "Allow Azure services" rules (0.0.0.0 to 0.0.0.0) without proper justification

### Storage Account Network Rules
- Setting default action to "Allow" which permits unrestricted access
- Overly broad IP allowlists in network access rules

## Best Practices

1. **Principle of Least Privilege**: Grant only the minimum permissions required for each use case
2. **Named Principals**: Always use specific, named service principals or managed identities instead of wildcards
3. **Regular Auditing**: Regularly review access policies to ensure they remain necessary and appropriately scoped
4. **Network Controls**: Combine policy-based access with network access controls where possible
5. **Managed Identities**: Prefer Azure AD managed identities over shared access policies when possible
6. **Specific Origins**: For CORS policies, specify exact allowed origins instead of using wildcards
7. **Default Deny**: Configure network rules with default deny and explicit allow rules for required access

## Remediation

When policy-based public access is detected:

1. **Remove Unnecessary Policies**: Delete any access policies that are no longer needed
2. **Scope Permissions**: Replace wildcard or overly broad permissions with specific, minimal permissions
3. **Use Managed Identities**: Replace shared access policies with Azure AD authentication where supported
4. **Network Restrictions**: Implement network access rules to limit policy-based access to known sources
5. **Audit Firewall Rules**: Review and remove overly permissive firewall rules
6. **Secure CORS**: Replace wildcard origins with specific, trusted domains 