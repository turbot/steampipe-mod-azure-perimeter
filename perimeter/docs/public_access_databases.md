## Databases Public Access

This benchmark checks for Azure database resources that may have public access enabled, including:

- Cosmos DB accounts with public network access enabled

Database resources with public network access enabled are potentially exposed to the internet, increasing the risk of unauthorized access attempts. For most production workloads, databases should use private endpoints or restricted network access to limit exposure. 