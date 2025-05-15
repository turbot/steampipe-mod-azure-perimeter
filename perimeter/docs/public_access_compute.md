# Compute Public Access

This benchmark focuses on identifying Azure compute resources that may have unintended public accessibility.

## Overview

Compute resources in Azure, such as virtual machines and App Services, can be directly exposed to the internet. This creates a significant attack surface that can be exploited if not properly secured. This benchmark evaluates whether compute resources have been configured with public IP addresses or unrestricted network access.

## Controls

This benchmark includes the following controls:

### Virtual machines should restrict public access
Ensures that virtual machines don't have public IP addresses directly assigned to them.

### App Services should restrict public access
Verifies that App Services use IP restrictions to control which networks can access them.

## Remediation

To remediate compute public access issues:

1. **Restrict VM public access**:
   - In the Azure Portal, navigate to the Virtual Machine
   - Select "Networking" under Settings
   - Review any public IP addresses and consider removing them
   - Use Azure Bastion, load balancers, or application gateways instead
   - Consider implementing Just-In-Time (JIT) VM access

2. **Secure App Services**:
   - In the Azure Portal, navigate to the App Service
   - Under Settings, select "Networking"
   - Configure access restrictions to limit access to specific IP ranges
   - Consider implementing private endpoints

3. **Use Azure CLI**:
   ```bash
   # Dissociate a public IP from a VM's network interface
   az network nic ip-config update --name <ip-config-name> --nic-name <nic-name> --resource-group <resource-group> --remove publicIpAddress
   
   # Add an access restriction to an App Service
   az webapp config access-restriction add --resource-group <resource-group> --name <app-name> --rule-name <rule-name> --action Allow --ip-address <ip-address>/32 --priority 100
   ```

## Additional Resources

- [Azure VM network security best practices](https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices)
- [App Service access restrictions](https://learn.microsoft.com/en-us/azure/app-service/app-service-ip-restrictions) 