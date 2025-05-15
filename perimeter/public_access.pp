benchmark "public_access" {
  title         = "Public Access"
  description   = "Resources in your Azure subscriptions should be protected from unwanted public access."
  documentation = file("./perimeter/docs/public_access.md")
  children = [
    benchmark.public_access_storage,
    benchmark.public_access_databases,
    benchmark.public_access_compute,
    benchmark.public_access_containers,
    benchmark.public_access_network
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "public_access_storage" {
  title         = "Storage Public Access"
  description   = "Storage resources in your Azure subscriptions should be protected from unwanted public access."
  documentation = file("./perimeter/docs/public_access_storage.md")
  children = [
    control.storage_account_restrict_public_access,
    control.storage_account_blob_containers_restrict_public_access
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "storage_account_restrict_public_access" {
  title       = "Storage accounts should restrict public access"
  description = "Azure Storage accounts should have the 'Allow Blob public access' property set to disabled to prevent unauthorized access."

  sql = <<-EOQ
    select
      a.id as resource,
      case
        when allow_blob_public_access = false then 'ok'
        else 'alarm'
      end as status,
      case
        when allow_blob_public_access = false then a.name || ' restricts public access to blobs.'
        else a.name || ' allows public access to blobs.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_storage_account a;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Storage"
  })
}

control "storage_account_blob_containers_restrict_public_access" {
  title       = "Storage account blob containers should restrict public access"
  description = "Blob containers in Azure Storage accounts should have their public access level set to 'Private' to prevent unauthorized access."

  sql = <<-EOQ
    select
      c.id as resource,
      case
        when c.public_access = 'None' then 'ok'
        else 'alarm'
      end as status,
      case
        when c.public_access = 'None' then c.name || ' restricts public access.'
        else c.name || ' allows public ' || c.public_access || ' access.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_storage_container c;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Storage"
  })
}

benchmark "public_access_databases" {
  title         = "Databases Public Access"
  description   = "Database resources in your Azure subscriptions should be protected from unwanted public access."
  documentation = file("./perimeter/docs/public_access_databases.md")
  children = [
    control.cosmosdb_account_restrict_public_access
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "cosmosdb_account_restrict_public_access" {
  title       = "Cosmos DB accounts should restrict public access"
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
        else c.name || ' restricts public network access.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_cosmosdb_account c;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/CosmosDB"
  })
}

benchmark "public_access_compute" {
  title         = "Compute Public Access"
  description   = "Compute resources in your Azure subscriptions should be protected from unwanted public access."
  documentation = file("./perimeter/docs/public_access_compute.md")
  children = [
    control.vm_restrict_public_access,
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "vm_restrict_public_access" {
  title       = "Virtual machines should restrict public access"
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
      azure_compute_virtual_machine vm;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Compute"
  })
}

benchmark "public_access_containers" {
  title         = "Containers Public Access"
  description   = "Container resources in your Azure subscriptions should be protected from unwanted public access."
  documentation = file("./perimeter/docs/public_access_containers.md")
  children = [
    control.aks_cluster_restrict_public_access,
    control.container_registry_restrict_public_access
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "aks_cluster_restrict_public_access" {
  title       = "AKS clusters should restrict public access"
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
      azure_kubernetes_cluster c;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/AKS"
  })
}

control "container_registry_restrict_public_access" {
  title       = "Container registries should restrict public access"
  description = "Azure Container Registries should be configured with private endpoints and network rules to restrict public access."

  sql = <<-EOQ
    select
      r.id as resource,
      case
        when public_network_access = 'Disabled' then 'ok'
        else 'alarm'
      end as status,
      case
        when public_network_access = 'Disabled' then r.name || ' restricts public network access.'
        else r.name || ' allows public network access.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_container_registry r;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/ContainerRegistry"
  })
}

benchmark "public_access_network" {
  title         = "Network Public Access"
  description   = "Network resources in your Azure subscriptions should be protected from unwanted public access."
  documentation = file("./perimeter/docs/public_access_network.md")
  children = [
    control.application_gateway_waf_enabled,
    control.network_security_group_no_public_access
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "application_gateway_waf_enabled" {
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
      azure_application_gateway g;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Network"
  })
}

control "network_security_group_no_public_access" {
  title       = "Network security groups should not allow unrestricted access from the internet"
  description = "Network security groups (NSGs) should not have rules that allow unrestricted inbound access from the internet (0.0.0.0/0) to any port."

  sql = <<-EOQ
    with nsg_with_public_access as (
      select
        id,
        name,
        jsonb_array_elements(security_rules) as rule
      from
        azure_network_security_group
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
          )
        then n.name || ' allows unrestricted inbound access with rule: ' || (rule ->> 'name')
        else n.name || ' does not allow unrestricted inbound access.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_subscription_id_qualifier_sql}
    from
      nsg_with_public_access n;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Network"
  })
} 