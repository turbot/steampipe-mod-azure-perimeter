## Databases Public Access

This benchmark checks for Azure database resources that may have public access enabled, including:

- SQL servers with firewall rules allowing access from 0.0.0.0 (the entire internet)
- Cosmos DB accounts with public network access enabled instead of using private endpoints

Publicly accessible database resources can be targeted by attackers for unauthorized access attempts and should be properly secured. 