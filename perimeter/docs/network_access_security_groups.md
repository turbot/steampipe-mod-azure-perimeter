## Security Group Access

This benchmark checks for Azure network security group configurations that may expose resources to unnecessary risk, including:

- Network security groups allowing RDP/SSH access from the internet
- Subnets without network security groups attached
- Overly permissive inbound security rules

Properly configured security groups are essential for controlling network traffic to Azure resources. 