benchmark "public_access" {
  title         = "Public Access"
  description   = "Resources should not be publicly accessible as they could expose sensitive data to bad actors."
  documentation = file("./perimeter/docs/public_access.md")
  children = [
    benchmark.public_access_settings,
    benchmark.resource_policy_public_access
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "resource_policy_public_access" {
  title         = "Resource Policy Public Access"
  description   = "Resources should not be publicly accessible through statements in their resource policies, access policies, or authorization rules."
  documentation = file("./perimeter/docs/resource_policy_public_access.md")
  children = [
    control.storage_account_cors_prohibit_public_access,
    control.cosmosdb_account_cors_prohibit_public_access,
    control.sql_server_firewall_rule_prohibit_public_access,
    control.storage_account_network_rules_prohibit_public_access
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

control "storage_account_cors_prohibit_public_access" {
  title       = "Storage account CORS policies should prohibit public access"
  description = "Azure Storage account Cross-Origin Resource Sharing (CORS) policies should not allow unrestricted access from any origin that could enable public access."

  sql = <<-EOQ
    with cors_configured_accounts as (
      select
        id,
        name,
        _ctx,
        region,
        resource_group,
        subscription_id,
        tags,
        blob_service_logging -> 'cors' -> 'corsRules' as cors_rules
      from
        azure_storage_account
        ${local.resource_group_filter_sql}
      where
        blob_service_logging -> 'cors' -> 'corsRules' is not null
        and jsonb_array_length(blob_service_logging -> 'cors' -> 'corsRules') > 0
    )
    select
      a.id as resource,
      case
        when cors_rules is null then 'ok'
        when jsonb_array_length(cors_rules) = 0 then 'ok'
        when cors_rules @> '[{"allowedOrigins": ["*"]}]' then 'alarm'
        when cors_rules::text like '%"allowedOrigins":%*%' then 'alarm'
        else 'ok'
      end as status,
      case
        when cors_rules is null then a.name || ' has no CORS rules configured.'
        when jsonb_array_length(cors_rules) = 0 then a.name || ' has no CORS rules configured.'
        when cors_rules @> '[{"allowedOrigins": ["*"]}]' then a.name || ' has CORS rules allowing access from any origin (*).'
        when cors_rules::text like '%"allowedOrigins":%*%' then a.name || ' has CORS rules that may allow public access.'
        else a.name || ' CORS rules do not allow unrestricted public access.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      cors_configured_accounts a;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Storage"
  })
}

control "cosmosdb_account_cors_prohibit_public_access" {
  title       = "Cosmos DB account CORS policies should prohibit public access"
  description = "Azure Cosmos DB account Cross-Origin Resource Sharing (CORS) policies should not allow unrestricted access from any origin that could enable public access."

  sql = <<-EOQ
    with cors_configured_accounts as (
      select
        id,
        name,
        _ctx,
        region,
        resource_group,
        subscription_id,
        tags,
        cors
      from
        azure_cosmosdb_account
        ${local.resource_group_filter_sql}
      where
        cors is not null
        and jsonb_array_length(cors) > 0
    )
    select
      c.id as resource,
      case
        when cors is null then 'ok'
        when jsonb_array_length(cors) = 0 then 'ok'
        when cors @> '[{"allowedOrigins": "*"}]' then 'alarm'
        when cors::text like '%"allowedOrigins":"*"%' then 'alarm'
        else 'ok'
      end as status,
      case
        when cors is null then c.name || ' has no CORS rules configured.'
        when jsonb_array_length(cors) = 0 then c.name || ' has no CORS rules configured.'
        when cors @> '[{"allowedOrigins": "*"}]' then c.name || ' has CORS rules allowing access from any origin (*).'
        when cors::text like '%"allowedOrigins":"*"%' then c.name || ' has CORS rules that may allow public access.'
        else c.name || ' CORS rules do not allow unrestricted public access.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      cors_configured_accounts c;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/CosmosDB"
  })
}

control "sql_server_firewall_rule_prohibit_public_access" {
  title       = "SQL Server firewall rules should prohibit public access"
  description = "Azure SQL Server firewall rules should not allow unrestricted access from the internet (0.0.0.0 to 255.255.255.255)."

  sql = <<-EOQ
    with servers_with_rules as (
      select
        id,
        name,
        _ctx,
        region,
        resource_group,
        subscription_id,
        tags,
        jsonb_array_elements(firewall_rules) as rule
      from
        azure_sql_server
        ${local.resource_group_filter_sql}
      where
        firewall_rules is not null
        and jsonb_array_length(firewall_rules) > 0
    )
    select
      s.id as resource,
      case
        when rule ->> 'startIpAddress' = '0.0.0.0' and rule ->> 'endIpAddress' = '255.255.255.255' then 'alarm'
        when rule ->> 'startIpAddress' = '0.0.0.0' and rule ->> 'endIpAddress' = '0.0.0.0' then 'alarm'
        else 'ok'
      end as status,
      case
        when rule ->> 'startIpAddress' = '0.0.0.0' and rule ->> 'endIpAddress' = '255.255.255.255' then s.name || ' has firewall rule ' || (rule ->> 'name') || ' allowing unrestricted internet access.'
        when rule ->> 'startIpAddress' = '0.0.0.0' and rule ->> 'endIpAddress' = '0.0.0.0' then s.name || ' has firewall rule ' || (rule ->> 'name') || ' allowing Azure services access.'
        else s.name || ' firewall rule ' || (rule ->> 'name') || ' does not allow unrestricted public access.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      servers_with_rules s;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/SQL"
  })
}

control "storage_account_network_rules_prohibit_public_access" {
  title       = "Storage account network rules should prohibit public access"
  description = "Azure Storage account network access rules should not allow unrestricted access from the internet when the default action is set to Allow."

  sql = <<-EOQ
    select
      a.id as resource,
      case
        when network_rule_default_action = 'Allow' then 'alarm'
        when network_rule_default_action = 'Deny' and network_ip_rules is not null 
          and jsonb_array_length(network_ip_rules) > 0 then 'info'
        else 'ok'
      end as status,
      case
        when network_rule_default_action = 'Allow' then a.name || ' network rules default action is Allow, which permits public access.'
        when network_rule_default_action = 'Deny' and network_ip_rules is not null 
          and jsonb_array_length(network_ip_rules) > 0 then a.name || ' has network IP rules configured with default Deny action.'
        else a.name || ' network rules do not allow unrestricted public access.'
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