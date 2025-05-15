# Network Access

This benchmark focuses on ensuring proper network controls are implemented to protect Azure resources from unauthorized access and malicious traffic.

## Overview

Network security is a critical component of a robust cloud security posture. This benchmark evaluates various network access controls in Azure, focusing on security groups, cross-tenant connections, and the proper management of public IP addresses.

## Benchmarks and Controls

This benchmark includes the following sub-benchmarks and controls:

### Network General Access
* Virtual network peering should restrict cross-tenant access
* Network Watcher should be enabled for all regions

### Security Group Access
* All subnets should be protected by a network security group
* Network security groups should restrict RDP access from the internet

### Public IP Access
* Public IP addresses should have proper tags
* Public IP addresses should be associated with a security rule

## Remediation

To remediate network access issues:

1. **General Network Security**:
   - Audit and restrict cross-tenant virtual network peering
   - Enable Network Watcher in all regions with active VNets for visibility and monitoring

2. **Security Groups**:
   - Ensure all subnets have an NSG attached
   - Review NSG rules and restrict RDP/SSH access from the internet
   - Implement Just-In-Time VM access instead of permanent inbound management ports

3. **Public IP Management**:
   - Maintain an inventory of all public IPs with proper tagging
   - Ensure each public IP has associated security rules
   - Implement Azure DDoS Protection for critical public endpoints

## Contributors

- Turbot
- Azure Security Team 