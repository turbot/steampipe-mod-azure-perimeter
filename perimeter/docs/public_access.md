# Public Access

## Overview

Public access in Azure can occur through two primary mechanisms:

1. **Configuration Settings** - Resources configured with public access flags or settings that allow internet access
2. **Resource Policies** - Access policies, authorization rules, or resource policies that grant public or overly permissive access

Both mechanisms can expose Azure resources to unauthorized access and should be carefully controlled.

## Public Access Settings

Many Azure services have configuration settings that explicitly control public access:

- **Storage Accounts** - `Allow Blob public access` setting and container-level public access
- **Cosmos DB** - `Public network access` settings and firewall rules  
- **Virtual Machines** - Direct assignment of public IP addresses
- **AKS Clusters** - Public vs private API server endpoints
- **Container Registries** - Public network access settings
- **Application Gateways** - Web Application Firewall enablement for public-facing services
- **Network Security Groups** - Rules allowing unrestricted inbound access from the internet

## Resource Policy Public Access  

Resources can also be exposed through policy-based access control mechanisms:

- **Key Vault Access Policies** - Policies that grant access to keys, secrets, and certificates
- **Service Bus Authorization Rules** - Shared access policies with overly broad permissions

These policy-based mechanisms can be particularly dangerous as they may bypass other security controls and can be harder to identify.

## Security Impact

Public access poses significant security risks:

1. **Data Exposure**: Sensitive data can be accessed by unauthorized users
2. **Compliance Violations**: May violate data protection regulations and organizational policies
3. **Attack Surface**: Increases the attack surface available to malicious actors
4. **Lateral Movement**: Can provide entry points for further compromise

## Best Practices

1. **Default Deny**: Configure resources to deny public access by default
2. **Least Privilege**: When public access is required, limit it to the minimum necessary scope
3. **Network Controls**: Use network access controls in addition to resource-level settings
4. **Regular Auditing**: Regularly review public access configurations across all resources
5. **Managed Identities**: Use Azure AD managed identities instead of access keys where possible
6. **Monitor Access**: Enable logging and monitoring for all public-facing resources

## Remediation

When public access is detected:

1. **Assess Necessity**: Determine if public access is actually required for business functionality
2. **Apply Network Restrictions**: Use network access controls to limit source IP ranges
3. **Enable Monitoring**: Ensure comprehensive logging and monitoring is in place
4. **Implement Authentication**: Where possible, replace anonymous access with authenticated access
5. **Regular Review**: Establish processes for regular review of public access configurations
