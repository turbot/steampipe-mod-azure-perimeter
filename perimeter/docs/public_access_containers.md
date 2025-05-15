# Containers Public Access

This benchmark focuses on identifying Azure container resources that may have unintended public accessibility.

## Overview

Container services in Azure, such as Container Registry and AKS clusters, can be configured with public access. This creates potential security risks if not properly restricted. This benchmark evaluates whether container resources have been configured with appropriate access controls to prevent unauthorized access.

## Controls

This benchmark includes the following controls:

### Container registries should restrict public access
Ensures that Azure Container Registry instances are not exposed to public networks without proper restrictions.

### AKS clusters should restrict public access to the API server
Verifies that Kubernetes API servers in AKS clusters are not directly accessible from the public internet.

## Remediation

To remediate container public access issues:

1. **Restrict Container Registry public access**:
   - In the Azure Portal, navigate to the Container Registry
   - Under Settings, select "Networking"
   - Choose "Selected networks" or "Disable public access"
   - Configure private endpoints for secure access
   - Implement Azure IAM for access control

2. **Secure AKS API server access**:
   - In the Azure Portal, navigate to the Kubernetes service
   - Select "Networking" under Settings
   - Enable "Private cluster" option for new clusters
   - For existing clusters, use authorized IP ranges to restrict API server access
   - Consider implementing Azure Private Link

3. **Using Azure CLI**:
   ```bash
   # Restrict Container Registry to selected networks
   az acr update --name <registry-name> --public-network-enabled false
   
   # Configure authorized IP ranges for AKS
   az aks update --resource-group <resource-group> --name <cluster-name> --api-server-authorized-ip-ranges <your-IP-range>
   
   # Create a private AKS cluster (new clusters only)
   az aks create --resource-group <resource-group> --name <cluster-name> --enable-private-cluster
   ```

## Additional Resources

- [Azure Container Registry network security](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-network-rules)
- [AKS private clusters](https://learn.microsoft.com/en-us/azure/aks/private-clusters)
- [Secure access to the API server in AKS](https://learn.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges) 