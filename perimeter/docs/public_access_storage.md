# Storage Public Access

This benchmark focuses on identifying Azure storage resources that may have unintended public accessibility.

## Overview

Azure Storage accounts and their containers can be configured to allow public access to data. While this might be necessary for some use cases like hosting website content, it often represents a significant security risk when enabled unnecessarily. This benchmark evaluates storage accounts and blob containers to ensure they're properly secured from public access.

## Controls

This benchmark includes the following controls:

### Storage accounts should restrict public access
Verifies that the "Allow Blob public access" property is set to disabled at the storage account level.

### Storage account blob containers should restrict public access
Ensures that blob containers have their public access level set to "Private" to prevent unauthorized access.

## Remediation

To remediate storage public access issues:

1. **Disable public access at the account level**:
   - In the Azure Portal, navigate to the Storage Account
   - Under Settings, select "Configuration"
   - Set "Allow Blob public access" to "Disabled"
   - Save the changes

2. **Set container access to private**:
   - In the Storage Account, go to "Containers"
   - For each container, set the "Public access level" to "Private (no anonymous access)"

3. **Use Azure CLI to disable public access**:
   ```bash
   # Disable at account level
   az storage account update --name <account-name> --resource-group <resource-group> --allow-blob-public-access false
   
   # Set container access to private
   az storage container set-permission --name <container-name> --account-name <account-name> --public-access off
   ```

## Additional Resources

- [Azure Storage security guide](https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations)
- [Configure anonymous public read access for containers and blobs](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure) 