# Security Group Access

This benchmark focuses on ensuring Network Security Groups (NSGs) are properly configured to protect Azure resources from unauthorized network access.

## Overview

Network Security Groups in Azure act as a distributed firewall for controlling traffic to and from Azure resources. Properly configured NSGs are an essential component of your network security posture. This benchmark evaluates whether NSGs are being used effectively and are configured according to security best practices.

## Controls

This benchmark includes the following controls:

### All subnets should be protected by a network security group
Ensures that every subnet in your Azure environment has an NSG attached to filter traffic.

### Network security groups should restrict RDP access from the internet
Verifies that NSGs do not allow unrestricted Remote Desktop Protocol (RDP) access from the internet, which could lead to brute force attacks.

## Remediation

To remediate security group access issues:

1. **Attach NSGs to all subnets**:
   - In the Azure Portal, navigate to Virtual Networks
   - For each VNet, select "Subnets" under Settings
   - For each subnet without an NSG, click on it and associate an NSG
   - Create new NSGs with appropriate rules if needed

2. **Restrict RDP access from the internet**:
   - In the Azure Portal, navigate to Network Security Groups
   - For each NSG, review the inbound security rules
   - Identify and modify any rules that allow RDP (port 3389) from Internet, *, or 0.0.0.0/0
   - Consider using Just-in-Time VM access or Azure Bastion instead

3. **Using Azure CLI**:
   ```bash
   # Associate an NSG with a subnet
   az network vnet subnet update --resource-group <resource-group> --vnet-name <vnet-name> --name <subnet-name> --network-security-group <nsg-name>
   
   # List all NSG rules allowing RDP from the internet
   az network nsg rule list --resource-group <resource-group> --nsg-name <nsg-name> --query "[?destinationPortRange=='3389' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='0.0.0.0/0' || sourceAddressPrefix=='Internet')].{Name:name, Priority:priority, Source:sourceAddressPrefix, Port:destinationPortRange}" --output table
   
   # Delete a permissive RDP rule
   az network nsg rule delete --resource-group <resource-group> --nsg-name <nsg-name> --name <rule-name>
   ```

## Additional Resources

- [Azure Network Security Group overview](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)
- [Azure VM security best practices](https://learn.microsoft.com/en-us/azure/security/fundamentals/virtual-machines-overview)
- [Just-in-Time VM access in Azure Security Center](https://learn.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-overview) 