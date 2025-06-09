# Public Access Settings

Resources should not be publicly accessible or exposed to the internet through configurations and settings.

This benchmark evaluates Azure resources that could be made publicly accessible through configuration flags, settings, and properties rather than through resource policies or IAM permissions. These settings often involve simple boolean flags or access level configurations that can inadvertently expose resources to the internet.

Common examples include:
- Storage account blob public access settings
- Database public network access flags  
- Virtual machine public IP assignments
- Container registry public access settings
- Network security group rules allowing unrestricted access

Regular monitoring and validation of these settings helps maintain a secure perimeter around your Azure infrastructure. 