## Network Public Access

Azure resources should implement proper network controls to protect against unauthorized network access.

This benchmark answers the following questions:

- Is SQL Server public network access enabled?
- Is Storage account public network access enabled?
- Is Cosmos DB account public network access enabled?
- Is Container Registry public network access enabled?

Properly managing public IP addresses is essential for maintaining a secure perimeter. Public IP addresses should be limited to only those resources that truly require internet connectivity, and they should use static allocation to ensure consistent security configurations.