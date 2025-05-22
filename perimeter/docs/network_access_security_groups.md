## Security Group Access

This benchmark checks for Azure network security group configurations that may expose resources to unnecessary risk, including:

- Subnets without network security groups attached, which leaves network segments unprotected
- Network security groups allowing RDP access from the internet (port 3389), which can lead to brute force attacks

Properly configured security groups are essential for controlling network traffic to Azure resources. Network security groups act as virtual firewalls that filter traffic between Azure resources and network segments based on rules.

The RDP control examines both sourceAddressPrefix and sourceAddressPrefixes array configurations to detect all possible internet exposure configurations. 