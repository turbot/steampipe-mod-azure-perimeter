# Shared Access

## Overview

Shared access in Azure occurs primarily through Azure Role-Based Access Control (RBAC), which provides fine-grained access management for Azure resources. Unlike public access, shared access involves deliberately granting permissions to specific principals (users, groups, or service principals) to access resources.

Azure shared access mechanisms include:

1. **Azure RBAC Role Assignments** - Assigning roles to principals at various scopes (subscription, resource group, resource)
2. **Cross-Subscription Access** - Role assignments that span multiple subscriptions
3. **Service Principal Access** - Role assignments for applications and services
4. **Privileged Role Assignments** - High-privilege roles like Owner, Contributor, User Access Administrator

## Azure RBAC Role Assignments

Azure RBAC uses role assignments to grant access to Azure resources. Each role assignment consists of:

- **Principal**: The user, group, service principal, or managed identity
- **Role Definition**: The set of permissions (e.g., Owner, Contributor, Reader)
- **Scope**: The level at which the role is assigned (management group, subscription, resource group, or resource)

### Common Role Assignment Patterns

- **Subscription-level assignments**: Broad access across all resources in a subscription
- **Resource group assignments**: Access to all resources within a specific resource group
- **Resource-level assignments**: Access to specific individual resources

## Security Concerns

Shared access through RBAC can introduce security risks if not properly managed:

1. **Over-privileged Access**: Granting more permissions than necessary
2. **Broad Scope**: Assigning roles at unnecessarily wide scopes
3. **Untrusted Principals**: Granting access to principals outside your trust boundary
4. **Privileged Role Sprawl**: Excessive assignments of high-privilege roles
5. **Cross-Subscription Access**: Uncontrolled access across subscription boundaries

## Cross-Subscription Access

Cross-subscription role assignments allow principals from one subscription to access resources in another subscription. This is particularly sensitive because:

- It crosses organizational boundaries
- It can bypass subscription-level controls
- It may violate compliance requirements
- It can create unexpected access paths

## Service Principal Access

Service principals represent applications and services in Azure AD. Special considerations include:

- **Application Identity**: Each service principal represents a specific application
- **Automated Access**: Service principals often have automated, programmatic access
- **Credential Management**: Service principals use certificates or secrets for authentication
- **Privilege Escalation**: Compromised service principals can be used to escalate privileges

## Privileged Role Assignments

Certain Azure roles provide elevated privileges and require special attention:

- **Owner**: Full access to all resources and the ability to assign roles to others
- **Contributor**: Full access to all resources but cannot assign roles
- **User Access Administrator**: Can manage access to Azure resources
- **Security Admin**: Can manage security policies and view security information

## Best Practices

1. **Principle of Least Privilege**: Grant only the minimum permissions required
2. **Trusted Principals Only**: Only grant access to known, trusted principals
3. **Scope Limitation**: Assign roles at the narrowest possible scope
4. **Regular Review**: Regularly audit and review role assignments
5. **Privileged Role Monitoring**: Carefully monitor assignments of privileged roles
6. **Cross-Subscription Controls**: Implement strict controls for cross-subscription access
7. **Service Principal Management**: Maintain an inventory of service principals and their purposes
8. **Automated Monitoring**: Use tools to monitor role assignment changes

## Compliance Considerations

Many compliance frameworks have requirements around access control:

- **SOC 2**: Requires logical access controls and regular access reviews
- **PCI DSS**: Mandates role-based access control for cardholder data environments
- **HIPAA**: Requires unique user identification and access controls for PHI
- **GDPR**: Requires appropriate technical measures for data protection

## Monitoring and Alerting

Implement monitoring for:

- New role assignments to privileged roles
- Cross-subscription role assignments
- Role assignments to external principals
- Changes to role assignments for critical resources
- Unusual patterns in role assignment activity

## Remediation

When inappropriate shared access is detected:

1. **Immediate Assessment**: Determine if the access is legitimate and necessary
2. **Scope Reduction**: Reduce the scope of role assignments where possible
3. **Role Refinement**: Replace broad roles with more specific, limited roles
4. **Principal Verification**: Verify the identity and trustworthiness of principals
5. **Access Removal**: Remove unnecessary or excessive role assignments
6. **Documentation**: Document the business justification for remaining assignments
7. **Monitoring Enhancement**: Implement enhanced monitoring for high-risk assignments 