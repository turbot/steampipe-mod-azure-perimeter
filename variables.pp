// Benchmarks and controls for specific services should override the "service" tag

locals {
  azure_perimeter_common_tags = {
    category = "Perimeter"
    plugin   = "azure"
    service  = "Azure"
  }
} 