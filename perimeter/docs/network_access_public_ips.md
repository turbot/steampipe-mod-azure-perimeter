# Public IP Access

This benchmark focuses on ensuring Public IP addresses in Azure are properly managed and secured.

## Overview

Public IP addresses in Azure provide direct internet accessibility to resources. While they are necessary for many use cases, they also present a significant security risk if not properly managed and secured. This benchmark evaluates whether Public IP addresses are correctly configured and associated with appropriate security controls.

## Controls

This benchmark may include the following controls:

### Public IP addresses should have proper tags
Ensures that all Public IP addresses have appropriate tags for resource management, cost attribution, and security tracking.

### Public IP addresses should be associated with a security rule
Verifies that Public IP addresses are associated with resources that have security rules (via NSGs or other security controls) to prevent unrestricted access.

## Remediation

To remediate public IP access issues:

1. **Apply proper tagging to Public IPs**:
   - In the Azure Portal, navigate to Public IP addresses
   - For each Public IP, select "Tags" under Settings
   - Add relevant tags for environment, owner, purpose, and security classification
   - Consider using automated tagging via Azure Policy

2. **Ensure Public IPs have security controls**:
   - For each Public IP, identify the associated resource (VM, Load Balancer, etc.)
   - Verify that the resource has an associated NSG with appropriate rules
   - Add security rules to restrict traffic to only necessary ports and source IPs
   - Consider implementing Azure DDoS Protection for critical endpoints

3. **Using Azure CLI**:
   ```bash
   # Add tags to a Public IP
   az network public-ip update --resource-group <resource-group> --name <public-ip-name> --tags Environment=Production Owner=Security Purpose=WebServer
   
   # List Public IPs with their associations
   az network public-ip list --query "[].{Name:name, IPAddress:ipAddress, AssociatedResource:ipConfiguration.id, ResourceGroup:resourceGroup}" --output table
   
   # Get NSG associated with a NIC that has a Public IP
   az network nic show --resource-group <resource-group> --name <nic-name> --query "networkSecurityGroup.id" --output tsv
   ```

## Additional Resources

- [Azure Public IP address management](https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses)
- [Azure network security best practices](https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices)
- [Azure DDoS Protection](https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview) 