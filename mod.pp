mod "azure_perimeter" {
  # Hub metadata
  title         = "Azure Perimeter"
  description   = "Is your Azure perimeter secure? Powerpipe and Steampipe can help you check your Azure subscriptions for public resources, resources shared with untrusted tenants, insecure network configurations and more."
  color         = "#0089D6"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/azure-perimeter.svg"
  categories    = ["azure", "compliance", "perimeter", "security"]

  opengraph {
    title       = "Powerpipe Mod for Azure Perimeter"
    description = "Is your Azure perimeter secure? Powerpipe and Steampipe can help you check your Azure subscriptions for public resources, resources shared with untrusted tenants, insecure network configurations and more."
    image       = "/images/mods/turbot/azure-perimeter-social-graphic.png"
  }

  require {
    plugin "azure" {
      min_version = "0.46.0"
    }
  }
} 