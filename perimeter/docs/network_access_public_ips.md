## Public IPs

This benchmark checks for Azure public IP addresses that may not be properly managed, including:

- Public IP addresses that may unnecessarily expose resources to the internet
- Public IP addresses configured with dynamic allocation method, which can lead to inconsistent security configurations

Properly monitoring and managing public IP addresses is essential for maintaining a secure perimeter. Public IP addresses should be limited to only those resources that truly require internet connectivity, and they should use static allocation to ensure consistent security configurations. 