benchmark "public_access" {
  title         = "Public Access"
  description   = "Resources should not be publicly accessible as they could expose sensitive data to bad actors."
  documentation = file("./perimeter/docs/public_access.md")
  children = [
    benchmark.public_access_settings
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "public_access_settings" {
  title         = "Public Access Settings"
  description   = "Resources should not be publicly accessible or exposed to the internet through configurations and settings."
  documentation = file("./perimeter/docs/public_access_settings.md")
  children = [
    control.storage_account_prohibit_public_access,
    control.storage_blob_container_prohibit_public_access,
    control.cosmosdb_account_prohibit_public_access,
    control.compute_vm_prohibit_public_access,
    control.kubernetes_cluster_prohibit_public_access,
    control.container_registry_prohibit_public_access,
    control.network_application_gateway_waf_enabled,
    control.network_security_group_prohibit_public_access
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "storage_account_prohibit_public_access" {
  title       = "Storage accounts should prohibit public access"
  description = "Azure Storage accounts should have the 'Allow Blob public access' property set to disabled to prevent unauthorized access."

  sql = <<-EOQ
    select
      a.id as resource,
      case
        when allow_blob_public_access = false then 'ok'
        else 'alarm'
      end as status,
      case
        when allow_blob_public_access = false then a.name || ' prohibits public access to blobs.'
        else a.name || ' allows public access to blobs.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_storage_account a
      ${local.resource_group_filter_sql};
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Storage"
  })
}

control "storage_blob_container_prohibit_public_access" {
  title       = "Storage account blob containers should prohibit public access"
  description = "Blob containers in Azure Storage accounts should have their public access level set to 'Private' to prevent unauthorized access."

  sql = <<-EOQ
    select
      c.id as resource,
      case
        when c.public_access = 'None' then 'ok'
        else 'alarm'
      end as status,
      case
        when c.public_access = 'None' then c.name || ' prohibits public access.'
        else c.name || ' allows public ' || c.public_access || ' access.'
      end as reason
      ${local.common_dimensions_global_sql}
    from
      azure_storage_container c
      ${local.resource_group_filter_sql};
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Storage"
  })
}

control "cosmosdb_account_prohibit_public_access" {
  title       = "Cosmos DB accounts should prohibit public access"
  description = "Azure Cosmos DB accounts should use private endpoints and restrict public network access to prevent unauthorized access."

  sql = <<-EOQ
    select
      c.id as resource,
      case
        when public_network_access = 'Enabled' then 'alarm'
        else 'ok'
      end as status,
      case
        when public_network_access = 'Enabled' then c.name || ' allows public network access.'
        else c.name || ' prohibits public network access.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_cosmosdb_account c
      ${local.resource_group_filter_sql};
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/CosmosDB"
  })
}

control "compute_vm_prohibit_public_access" {
  title       = "Virtual machines should prohibit public access"
  description = "Azure virtual machines should not have public IP addresses directly assigned to them. Use Azure Bastion, load balancers, or application gateways to control access."

  sql = <<-EOQ
    select
      vm.id as resource,
      case
        when vm.public_ips is null or jsonb_array_length(vm.public_ips) = 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when vm.public_ips is null or jsonb_array_length(vm.public_ips) = 0 then vm.name || ' has no public IP addresses.'
        else vm.name || ' has ' || jsonb_array_length(vm.public_ips) || ' public IP address(es).'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_compute_virtual_machine vm
      ${local.resource_group_filter_sql};
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Compute"
  })
}

control "kubernetes_cluster_prohibit_public_access" {
  title       = "AKS clusters should prohibit public access"
  description = "Azure Kubernetes Service (AKS) clusters should use private API server endpoints to restrict public access to the control plane."

  sql = <<-EOQ
    select
      c.id as resource,
      case
        when api_server_access_profile ->> 'enablePrivateCluster' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when api_server_access_profile ->> 'enablePrivateCluster' = 'true' then c.name || ' API server is private.'
        else c.name || ' API server is public.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_kubernetes_cluster c
      ${local.resource_group_filter_sql};
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/AKS"
  })
}

control "container_registry_prohibit_public_access" {
  title       = "Container registries should prohibit public access"
  description = "Azure Container Registries should be configured with private endpoints and network rules to restrict public access."

  sql = <<-EOQ
    select
      r.id as resource,
      case
        when public_network_access = 'Disabled' then 'ok'
        else 'alarm'
      end as status,
      case
        when public_network_access = 'Disabled' then r.name || ' prohibits public network access.'
        else r.name || ' allows public network access.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_container_registry r
      ${local.resource_group_filter_sql};
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/ContainerRegistry"
  })
}

control "network_application_gateway_waf_enabled" {
  title       = "Application Gateway should have WAF enabled"
  description = "Azure Application Gateway instances exposed to the internet should have Web Application Firewall (WAF) enabled to protect against common web vulnerabilities."

  sql = <<-EOQ
    select
      g.id as resource,
      case
        when g.web_application_firewall_configuration is null then 'alarm'
        when (g.web_application_firewall_configuration ->> 'enabled')::boolean = false then 'alarm'
        else 'ok'
      end as status,
      case
        when g.web_application_firewall_configuration is null then g.name || ' has no WAF enabled.'
        when (g.web_application_firewall_configuration ->> 'enabled')::boolean = false then g.name || ' has WAF disabled.'
        else g.name || ' has WAF enabled.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_application_gateway g
      ${local.resource_group_filter_sql};
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Network"
  })
}

control "network_security_group_prohibit_public_access" {
  title       = "Network security groups should prohibit unrestricted access from the internet"
  description = "Network security groups (NSGs) should not have rules that allow unrestricted inbound access from the internet (0.0.0.0/0) to any port."

  sql = <<-EOQ
    with nsg_with_public_access as (
      select
        id,
        name,
        _ctx,
        region,
        resource_group,
        subscription_id,
        tags,
        jsonb_array_elements(security_rules) as rule
      from
        azure_network_security_group
        ${local.resource_group_filter_sql}
      where
        jsonb_typeof(security_rules) = 'array'
    )
    select
      n.id as resource,
      case
        when rule -> 'properties' ->> 'access' = 'Allow'
          and rule -> 'properties' ->> 'direction' = 'Inbound'
          and (
            rule -> 'properties' ->> 'sourceAddressPrefix' = '*'
            or rule -> 'properties' ->> 'sourceAddressPrefix' = '0.0.0.0/0'
            or rule -> 'properties' ->> 'sourceAddressPrefix' = 'Internet'
            or (
              rule -> 'properties' ->> 'sourceAddressPrefix' is null
              and (
                rule -> 'properties' -> 'sourceAddressPrefixes' @> '["*"]'
                or rule -> 'properties' -> 'sourceAddressPrefixes' @> '["0.0.0.0/0"]'
                or rule -> 'properties' -> 'sourceAddressPrefixes' @> '["Internet"]'
              )
            )
          )
        then 'alarm'
        else 'ok'
      end as status,
      case
        when rule -> 'properties' ->> 'access' = 'Allow'
          and rule -> 'properties' ->> 'direction' = 'Inbound'
          and (
            rule -> 'properties' ->> 'sourceAddressPrefix' = '*'
            or rule -> 'properties' ->> 'sourceAddressPrefix' = '0.0.0.0/0'
            or rule -> 'properties' ->> 'sourceAddressPrefix' = 'Internet'
            or (
              rule -> 'properties' ->> 'sourceAddressPrefix' is null
              and (
                rule -> 'properties' -> 'sourceAddressPrefixes' @> '["*"]'
                or rule -> 'properties' -> 'sourceAddressPrefixes' @> '["0.0.0.0/0"]'
                or rule -> 'properties' -> 'sourceAddressPrefixes' @> '["Internet"]'
              )
            )
          )
        then n.name || ' allows unrestricted inbound access with rule: ' || (rule ->> 'name')
        else n.name || ' prohibits unrestricted inbound access.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      nsg_with_public_access n;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Network"
  })
} 