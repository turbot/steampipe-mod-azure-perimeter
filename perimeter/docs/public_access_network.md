# Network Public Access

This benchmark focuses on identifying Azure networking resources that may have unintended public accessibility.

## Overview

Networking components in Azure, such as public IP addresses and load balancers, are designed to enable public internet connectivity. However, they need to be properly configured and secured to prevent unauthorized access. This benchmark evaluates whether network resources have been configured with appropriate security controls.

## Controls

This benchmark includes the following controls:

### Public IP addresses should be attached to valid resources
Ensures that all public IP addresses are associated with active resources and not orphaned or unused, which could lead to security gaps.

### Public load balancers should restrict access to necessary ports
Verifies that load balancer rules restrict public access to only the necessary ports and services.

## Remediation

To remediate network public access issues:

1. **Manage public IP addresses**:
   - In the Azure Portal, navigate to Public IP addresses
   - Identify any public IPs that are not attached to active resources
   - Delete unused public IP addresses
   - For necessary public IPs, ensure they are protected by NSGs or Firewall rules

2. **Secure public load balancers**:
   - In the Azure Portal, navigate to Load balancers
   - For each public load balancer, review the frontend IP configurations and load balancing rules
   - Restrict inbound NAT rules to only necessary ports
   - Implement NSGs for the backend pools
   - Consider using Azure Application Gateway with WAF for HTTP/HTTPS traffic

3. **Using Azure CLI**:
   ```bash
   # List public IPs with their allocation status
   az network public-ip list --query "[].{Name:name, IPAddress:ipAddress, Attached:ipConfiguration.id, ResourceGroup:resourceGroup}" --output table
   
   # Delete an unused public IP
   az network public-ip delete --resource-group <resource-group> --name <public-ip-name>
   
   # List load balancer rules
   az network lb rule list --resource-group <resource-group> --lb-name <load-balancer-name> --query "[].{Name:name, Protocol:protocol, FrontendPort:frontendPort, BackendPort:backendPort}" --output table
   ```

## Additional Resources

- [Azure Load Balancer security](https://learn.microsoft.com/en-us/azure/load-balancer/security-baseline)
- [Azure Public IP address management](https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses)
- [Network security recommendations for Azure services](https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices) 