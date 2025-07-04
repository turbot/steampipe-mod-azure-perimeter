// Benchmarks and controls for specific services should override the "service" tag

locals {
  azure_perimeter_common_tags = {
    category = "Perimeter"
    plugin   = "azure"
    service  = "Azure"
  }
}

variable "common_dimensions" {
  type        = list(string)
  description = "A list of common dimensions to add to each control."
  # Define which common dimensions should be added to each control.
  # - connection_name (_ctx ->> 'connection_name')
  # - region
  # - resource_group
  # - subscription
  # - subscription_id
  default = ["resource_group", "subscription"]
}

variable "tag_dimensions" {
  type        = list(string)
  description = "A list of tags to add as dimensions to each control."
  # A list of tag names to include as dimensions for resources that support
  # tags (e.g. "department", "environment"). Default to empty since tag names are
  # a personal choice
  default = []
}

variable "database" {
  type        = connection.steampipe
  description = "Steampipe database connection string."
  default     = connection.steampipe.default
}

locals {
  # Local internal variable to build the SQL select clause for common
  # dimensions using a table name qualifier if required. Do not edit directly.
  common_dimensions_qualifier_sql = <<-EOQ
  %{~if contains(var.common_dimensions, "connection_name")}, __QUALIFIER___ctx ->> 'connection_name' as connection_name%{endif~}
  %{~if contains(var.common_dimensions, "region")}, __QUALIFIER__region as region%{endif~}
  %{~if contains(var.common_dimensions, "resource_group")}, __QUALIFIER__resource_group as resource_group%{endif~}
  %{~if contains(var.common_dimensions, "subscription_id")}, __QUALIFIER__subscription_id as subscription_id%{endif~}
  EOQ

  common_dimensions_global_qualifier_sql = <<-EOQ
  %{~if contains(var.common_dimensions, "connection_name")}, __QUALIFIER___ctx ->> 'connection_name' as connection_name%{endif~}
  %{~if contains(var.common_dimensions, "resource_group")}, __QUALIFIER__resource_group as resource_group%{endif~}
  %{~if contains(var.common_dimensions, "subscription_id")}, __QUALIFIER__subscription_id as subscription_id%{endif~}
  EOQ

  common_dimensions_subscription_id_qualifier_sql = <<-EOQ
  %{~if contains(var.common_dimensions, "connection_name")}, __QUALIFIER___ctx ->> 'connection_name' as connection_name%{endif~}
  %{~if contains(var.common_dimensions, "subscription_id")}, __QUALIFIER__subscription_id as subscription_id%{endif~}
  EOQ

  common_dimensions_qualifier_subscription_sql = <<-EOQ
  %{~if contains(var.common_dimensions, "subscription")}, __QUALIFIER__display_name as subscription%{endif~}
  EOQ

  # Local internal variable to build the SQL select clause for tag
  # dimensions. Do not edit directly.
  tag_dimensions_qualifier_sql = <<-EOQ
  %{~for dim in var.tag_dimensions},  __QUALIFIER__tags ->> '${dim}' as "${replace(dim, "\"", "\"\"")}"%{endfor~}
  EOQ
}

locals {
  # Local internal variable with the full SQL select clause for common
  # and tag dimensions. Do not edit directly.
  common_dimensions_sql                 = replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "")
  common_dimensions_global_sql          = replace(local.common_dimensions_global_qualifier_sql, "__QUALIFIER__", "")
  common_dimensions_subscription_sql    = replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "")
  common_dimensions_subscription_id_sql = replace(local.common_dimensions_subscription_id_qualifier_sql, "__QUALIFIER__", "")
  tag_dimensions_sql                    = replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "")
}
