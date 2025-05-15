# Network General Access

This benchmark focuses on ensuring Azure resources implement proper general network controls to protect against unauthorized access.

## Overview

Network security in Azure requires implementing multiple layers of controls. This benchmark focuses on general network access settings that apply broadly across your Azure environment, including cross-tenant protections and network monitoring capabilities.

## Controls

This benchmark includes the following controls:

### Virtual network peering should restrict cross-tenant access
Verifies that virtual network peering connections are limited to within the same tenant to prevent unauthorized cross-tenant network access.

### Network Watcher should be enabled for all regions
Ensures that Network Watcher is enabled in all regions where you have virtual networks to provide monitoring and diagnostic capabilities.

## Remediation

To remediate general network access issues:

1. **Restrict cross-tenant VNet peering**:
   - In the Azure Portal, navigate to Virtual Networks
   - For each VNet, review "Peerings" under Settings
   - Identify and remove any peerings to VNets in different tenants
   - If cross-tenant connectivity is required, consider using ExpressRoute or VPN connections with proper security controls

2. **Enable Network Watcher**:
   - In the Azure Portal, navigate to Network Watcher
   - Review the regions where Network Watcher is enabled
   - Enable Network Watcher for all regions where you have VNets
   - Configure NSG flow logs and traffic analytics

3. **Using Azure CLI**:
   ```bash
   # List virtual network peerings with remote VNet IDs
   az network vnet peering list --resource-group <resource-group> --vnet-name <vnet-name> --query "[].{Name:name, RemoteVnet:remoteVirtualNetwork.id}" --output table
   
   # Enable Network Watcher in a region
   az network watcher configure --resource-group NetworkWatcherRG --locations <region> --enabled true
   ```

## Additional Resources

- [Azure Virtual Network peering security](https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-peering-overview#security-for-virtual-network-peering)
- [Azure Network Watcher overview](https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview) 