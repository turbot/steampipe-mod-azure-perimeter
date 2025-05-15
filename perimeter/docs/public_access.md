# Public Access

This benchmark focuses on identifying Azure resources that may have unintended public accessibility, which can expose your organization to security risks. 

## Overview

Public access to cloud resources represents one of the most common vectors for security breaches. This benchmark evaluates various Azure resources to ensure they're not inadvertently exposed to the public internet. It checks storage accounts, databases, compute resources, containers, and networking components.

## Benchmarks and Controls

This benchmark includes the following sub-benchmarks and controls:

### Storage Public Access
* Storage accounts should restrict public access
* Storage account blob containers should restrict public access

### Databases Public Access
* SQL servers should not have public access via firewall rules
* Cosmos DB accounts should restrict public access

### Compute Public Access
* Virtual machines should restrict public access
* App Services should restrict public access

### Containers Public Access
* Container registries should restrict public access
* AKS clusters should restrict public access to the API server

### Network Public Access
* Public IP addresses should be attached to valid resources
* Public load balancers should restrict access to necessary ports

## Remediation

To remediate public access issues:

1. **Storage**: Disable blob public access at the account level and set container access levels to private.
2. **Databases**: Remove any firewall rules that allow access from 0.0.0.0 and enable private endpoints where possible.
3. **Compute**: Use private endpoints, application gateways, or load balancers instead of directly exposing VMs or apps.
4. **Containers**: Implement private registries and use private AKS clusters or restrict API server access.
5. **Networking**: Audit and remove unnecessary public IP addresses and implement NSGs to restrict access to only necessary ports.

## Contributors

- Turbot
- Azure Security Team 