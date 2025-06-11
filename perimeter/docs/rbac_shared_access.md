# RBAC Shared Access

## Overview

Azure Role-Based Access Control (RBAC) is the primary mechanism for controlling access to Azure resources. RBAC allows you to grant specific permissions to users, groups, and service principals at different scopes within your Azure environment.

## How Azure RBAC Works

Azure RBAC operates on three key components:

1. **Security Principal**: Who needs access (user, group, service principal, managed identity)
2. **Role Definition**: What they can do (set of permissions)
3. **Scope**: Where they have access (management group, subscription, resource group, resource)

### Role Assignment Structure

A role assignment combines these three components:
```
Security Principal + Role Definition + Scope = Role Assignment
```

## Trusted vs Untrusted Principals

### Trusted Principals

Trusted principals are identities that your organization explicitly authorizes to access Azure resources:

- **Internal Users**: Employees and contractors with verified identities
- **Approved Service Principals**: Applications and services registered and managed by your organization
- **Managed Identities**: Azure-managed identities for Azure services
- **Authorized Groups**: Azure AD groups containing verified members

### Untrusted Principals

Untrusted principals are identities that should not have access to your resources:

- **External Users**: Users from other tenants or organizations
- **Unmanaged Applications**: Service principals not registered with your organization
- **Unknown Identities**: Principals whose ownership or purpose is unclear
- **Compromised Accounts**: Accounts that may have been compromised

## Cross-Subscription Access Control

Cross-subscription role assignments require special consideration because they:

- Span organizational boundaries
- May bypass subscription-level governance
- Can create complex access patterns
- Require coordination between subscription owners

### Best Practices for Cross-Subscription Access

1. **Explicit Approval**: Require formal approval for cross-subscription access
2. **Limited Scope**: Restrict cross-subscription access to specific resource groups or resources
3. **Regular Review**: Conduct frequent reviews of cross-subscription assignments
4. **Documentation**: Maintain clear documentation of business justifications
5. **Monitoring**: Implement enhanced monitoring for cross-subscription activities

## Service Principal Access Management

Service principals present unique security challenges:

### Service Principal Types

- **Application Service Principals**: Represent multi-tenant applications
- **User-Assigned Managed Identities**: Explicitly created and managed identities
- **System-Assigned Managed Identities**: Automatically created with Azure resources

### Service Principal Security Considerations

1. **Credential Management**: Secure handling of certificates and secrets
2. **Scope Limitation**: Grant minimum necessary permissions
3. **Regular Rotation**: Rotate credentials according to security policies
4. **Monitoring**: Track service principal activities and access patterns
5. **Inventory Management**: Maintain accurate inventory of all service principals

## Common RBAC Anti-Patterns

### Over-Privileged Assignments
- Granting Owner when Contributor is sufficient
- Using subscription scope when resource group scope is adequate
- Assigning multiple overlapping roles

### Broad Access Patterns
- Generic "Admin" groups with excessive permissions
- Service principals with subscription-level access
- Cross-subscription assignments without justification

### Poor Lifecycle Management
- Stale role assignments for departed employees
- Orphaned service principals
- Unreviewed long-standing assignments

## Monitoring and Auditing

### Key Metrics to Track

1. **Role Assignment Changes**: New, modified, and deleted assignments
2. **Privileged Access**: Assignments involving high-privilege roles
3. **Cross-Subscription Activity**: Access patterns across subscription boundaries
4. **Service Principal Usage**: Authentication and resource access by service principals
5. **Failed Access Attempts**: Unauthorized access attempts

### Audit Considerations

- **Regular Access Reviews**: Periodic validation of role assignments
- **Segregation of Duties**: Ensuring appropriate separation of responsibilities
- **Compliance Reporting**: Generating reports for compliance frameworks
- **Change Tracking**: Maintaining audit trails for all RBAC changes

## Security Recommendations

### For Users and Groups
1. Use Azure AD groups instead of individual user assignments
2. Implement just-in-time access using Privileged Identity Management (PIM)
3. Require multi-factor authentication for privileged roles
4. Regularly review and clean up unused assignments

### For Service Principals
1. Use managed identities when possible instead of service principals
2. Implement certificate-based authentication over secrets
3. Rotate credentials regularly
4. Monitor service principal activities closely

### For Cross-Subscription Access
1. Establish clear governance processes
2. Implement approval workflows
3. Use Azure Lighthouse for managed service provider scenarios
4. Document all cross-subscription relationships

## Incident Response

When unauthorized or inappropriate access is detected:

1. **Immediate Response**
   - Assess the scope of potential impact
   - Temporarily disable suspicious accounts if necessary
   - Gather relevant logs and evidence

2. **Investigation**
   - Determine how the access was granted
   - Identify any data or resources that may have been accessed
   - Review related role assignments and activities

3. **Remediation**
   - Remove inappropriate role assignments
   - Strengthen controls to prevent recurrence
   - Update documentation and procedures
   - Implement additional monitoring if needed

4. **Recovery**
   - Verify that all unauthorized access has been removed
   - Implement compensating controls if necessary
   - Update incident response procedures based on lessons learned 