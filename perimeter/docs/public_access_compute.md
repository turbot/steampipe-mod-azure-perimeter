## Compute Public Access

This benchmark checks for Azure compute resources that may have public access enabled, including:

- Virtual machines with public IP addresses directly attached

Virtual machines with direct public IP address assignments are exposed to the internet, which increases their attack surface. For better security, it's recommended to use intermediary services like Azure Application Gateway, Load Balancer, or Azure Bastion for controlled access to virtual machines. 