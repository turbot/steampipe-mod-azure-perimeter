## Public IPs

This benchmark checks for Azure public IP addresses that may not be properly managed, including:

- Compute VM no public IP
- Network interface not attached to public IP
- Network public IP require static allocation

Properly managing public IP addresses is essential for maintaining a secure perimeter. Public IP addresses should be limited to only those resources that truly require internet connectivity, and they should use static allocation to ensure consistent security configurations. 