## Storage Public Access

This benchmark checks for Azure Storage resources that may have public access enabled, including:

- Storage accounts with "Allow Blob public access" enabled at the account level
- Storage account blob containers with public access level not set to "Private"

Storage resources with public access settings enabled can expose data to anyone on the internet, creating potential security risks if not properly secured and managed. 