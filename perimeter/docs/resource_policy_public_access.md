# Resource Policy Public Access

This benchmark checks for Azure resources that may be publicly accessible through configuration flags, settings, and properties rather than through resource policies or IAM permissions. These settings often involve simple boolean flags or access level configurations that can inadvertently expose resources to the internet.

This benchmark checks for:
- Cosmos DB account cors policy public access

Properly managing public access settings is essential for maintaining a secure perimeter. Public access settings should be carefully managed to ensure that only authorized principals have access to resources.