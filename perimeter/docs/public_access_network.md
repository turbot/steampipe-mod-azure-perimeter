## Network Public Access

This benchmark checks for Azure networking resources that may have public access enabled, including:

- Application Gateways without Web Application Firewall (WAF) enabled, leaving them vulnerable to common web exploits
- Network security groups with rules that allow unrestricted inbound access from the internet (0.0.0.0/0, *, or Internet), through both direct sourceAddressPrefix settings and sourceAddressPrefixes arrays

Network resources with inadequate public access protections can become entry points for attackers. Application Gateways exposed to the internet should have WAF enabled to protect against common web vulnerabilities, and network security groups should be carefully configured to restrict internet traffic to only what is necessary. 