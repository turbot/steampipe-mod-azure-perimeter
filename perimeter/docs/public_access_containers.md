## Containers Public Access

This benchmark checks for Azure container resources that may have public access enabled, including:

- AKS clusters with public API server endpoints instead of private endpoints
- Container registries with public network access enabled

Container services with public access can be targeted by attackers. For AKS clusters, the API server is particularly sensitive as it controls the entire Kubernetes environment. For container registries, public access may expose container images and allow unauthorized pulls or potentially pushes. 