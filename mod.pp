mod "azure_perimeter" {
  # Hub metadata
  title         = "Azure Perimeter"
  description   = "Run security controls across all your Azure subscriptions to look for resources that are publicly accessible, shared with untrusted accounts, have insecure network configurations, and more across all your Azure subscriptions using Powerpipe and Steampipe."
  color         = "#0089D6"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/azure-perimeter.svg"
  categories    = ["azure", "public cloud", "perimeter", "security"]

  opengraph {
    title       = "Powerpipe Mod for Azure Perimeter"
    description = "Run security controls across all your Azure subscriptions to look for resources that are publicly accessible, shared with untrusted accounts, have insecure network configurations, and more across all your Azure subscriptions using Powerpipe and Steampipe."
    image       = "/images/mods/turbot/azure-perimeter-social-graphic.png"
  }

  require {
    plugin "azure" {
      min_version = "0.46.0"
    }
  }
} 