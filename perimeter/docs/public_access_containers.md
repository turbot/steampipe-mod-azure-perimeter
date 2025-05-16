## Containers Public Access

This benchmark checks for Azure container resources that may have public access enabled, including:

- Container registries with public network access enabled
- AKS clusters with API server endpoints accessible from the public internet
- Container instances with public IP addresses

Publicly accessible container resources can expose sensitive data and services if not properly secured. 