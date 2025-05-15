# Databases Public Access

This benchmark focuses on identifying Azure database resources that may have unintended public accessibility.

## Overview

Database services in Azure can be configured to allow direct access from the public internet. While sometimes necessary for specific use cases, public access to databases represents a significant security risk when enabled unnecessarily. This benchmark evaluates SQL servers and Cosmos DB accounts to ensure they're properly secured from public access.

## Controls

This benchmark includes the following controls:

### SQL servers should not have public access via firewall rules
Verifies that SQL server firewall rules don't allow access from 0.0.0.0 (the entire internet).

### Cosmos DB accounts should restrict public access
Ensures that Cosmos DB accounts have public network access disabled in favor of private endpoints.

## Remediation

To remediate database public access issues:

1. **Remove public access to SQL servers**:
   - In the Azure Portal, navigate to the SQL server
   - Under Security, select "Networking"
   - Remove any firewall rules with start IP address 0.0.0.0
   - Consider implementing private endpoints instead

2. **Restrict public access to Cosmos DB**:
   - In the Azure Portal, navigate to the Cosmos DB account
   - Under Settings, select "Networking"
   - Select "Disable public access"
   - Configure private endpoints for secure access

3. **Use Azure CLI to limit access**:
   ```bash
   # Remove public firewall rule from SQL Server
   az sql server firewall-rule delete --resource-group <resource-group> --server <server-name> --name <rule-name>
   
   # Disable public network access for Cosmos DB
   az cosmosdb update --name <account-name> --resource-group <resource-group> --disable-public-network true
   ```

## Additional Resources

- [Configure Azure SQL Database server-level firewall rules](https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure)
- [Configure private endpoints for Azure Cosmos DB](https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-private-endpoints) 