benchmark "shared_access" {
  title         = "Shared Access"
  description   = "Resources in your Azure subscriptions should only be shared with trusted subscriptions and tenants. Inappropriate sharing can lead to data leakage or unauthorized access."
  documentation = file("./perimeter/docs/shared_access.md")
  children = [
    benchmark.shared_access_lighthouse,
    benchmark.shared_access_storage,
    benchmark.shared_access_peering
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "shared_access_lighthouse" {
  title         = "Lighthouse Shared Access"
  description   = "Azure Lighthouse should only delegate resources to trusted tenants and users."
  documentation = file("./perimeter/docs/shared_access_lighthouse.md")
  children = [
    control.lighthouse_delegation_to_trusted_tenants,
    control.lighthouse_delegation_with_proper_authorization
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "lighthouse_delegation_to_trusted_tenants" {
  title       = "Lighthouse delegations should only be to trusted tenants"
  description = "Azure Lighthouse delegations should only be established with trusted tenants to prevent unauthorized access to your Azure resources."

  sql = <<-EOQ
    with trusted_tenant_ids as (
      select
        unnest(${jsonb(var.trusted_subscriptions)}) as id
    )
    select
      rd.id as resource,
      case
        when t.id is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when t.id is not null then rd.name || ' is delegated to a trusted tenant.'
        else rd.name || ' is delegated to an untrusted tenant: ' || rd.managing_tenant_id
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_lighthouse_registration_definition rd
      left join trusted_tenant_ids t on rd.managing_tenant_id = t.id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Lighthouse"
  })
}

control "lighthouse_delegation_with_proper_authorization" {
  title       = "Lighthouse delegations should use proper authorization levels"
  description = "Azure Lighthouse delegations should be configured with the principle of least privilege, providing only the minimum permissions necessary for the delegated tasks."

  sql = <<-EOQ
    with authorization_checks as (
      select
        id,
        name,
        authorization,
        case when 
          authorization ->> 'roleDefinitionId' = '/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c' or  -- Contributor
          authorization ->> 'roleDefinitionId' = '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635' or  -- Owner
          authorization ->> 'roleDefinitionId' like '%/providers/Microsoft.Authorization/roleDefinitions/%'  -- Any custom role with high permissions
        then true
        else false
        end as has_high_permissions
      from
        azure_lighthouse_registration_definition,
        jsonb_array_elements(authorization_details) as authorization
    )
    select
      ac.id as resource,
      case
        when ac.has_high_permissions then 'alarm'
        else 'ok'
      end as status,
      case
        when ac.has_high_permissions then ac.name || ' has delegation with high permission levels.'
        else ac.name || ' has appropriate permission levels for delegation.'
      end as reason
      ${local.common_dimensions_sql}
    from
      authorization_checks ac;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Lighthouse"
  })
}

benchmark "shared_access_storage" {
  title         = "Storage Shared Access"
  description   = "Azure Storage resources should be properly secured when shared across subscriptions or externally."
  documentation = file("./perimeter/docs/shared_access_storage.md")
  children = [
    control.storage_account_shared_access_key_enabled,
    control.storage_account_cors_rules_restricted
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "storage_account_shared_access_key_enabled" {
  title       = "Storage accounts should have shared access key authentication enabled"
  description = "Azure Storage accounts should have shared access key authentication enabled to maintain control over data access."

  sql = <<-EOQ
    select
      a.id as resource,
      case
        when a.shared_access_key_enabled = false then 'alarm'
        else 'ok'
      end as status,
      case
        when a.shared_access_key_enabled = false then a.name || ' has shared access key authentication disabled.'
        else a.name || ' has shared access key authentication enabled.'
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

control "storage_account_cors_rules_restricted" {
  title       = "Storage accounts should restrict CORS rules"
  description = "Azure Storage accounts should have Cross-Origin Resource Sharing (CORS) rules that only allow trusted domains to access your storage resources."

  sql = <<-EOQ
    with cors_rules as (
      select
        id,
        name,
        jsonb_array_elements(cors_rules) as rule
      from
        azure_storage_account
      where
        cors_rules is not null and
        jsonb_array_length(cors_rules) > 0
    )
    select
      cr.id as resource,
      case
        when cr.rule ->> 'allowedOrigins' = '*' then 'alarm'
        else 'ok'
      end as status,
      case
        when cr.rule ->> 'allowedOrigins' = '*' then cr.name || ' has CORS rule allowing all origins.'
        else cr.name || ' has restricted CORS rules.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      cors_rules cr;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Storage"
  })
}

benchmark "shared_access_peering" {
  title         = "Network Peering Shared Access"
  description   = "Azure virtual networks should only be peered with trusted networks to maintain security boundaries."
  documentation = file("./perimeter/docs/shared_access_peering.md")
  children = [
    control.vnet_peering_with_trusted_networks,
    control.vnet_peering_gateway_transit_restricted
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "vnet_peering_with_trusted_networks" {
  title       = "Virtual network peering should only be established with trusted networks"
  description = "Azure virtual network peering connections should only be established with trusted networks to prevent unauthorized access to your resources."

  sql = <<-EOQ
    select
      p.id as resource,
      case
        when p.peering_state != 'Connected' then 'info'
        when p.remote_virtual_network_id is null then 'alarm' 
        else 'ok'
      end as status,
      case
        when p.peering_state != 'Connected' then p.name || ' peering is in ' || p.peering_state || ' state.'
        when p.remote_virtual_network_id is null then p.name || ' has no remote virtual network configured.'
        else p.name || ' is peered with virtual network ' || p.remote_virtual_network_id
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_virtual_network_peering p;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Network"
  })
}

control "vnet_peering_gateway_transit_restricted" {
  title       = "Virtual network peering gateway transit should be restricted"
  description = "Azure virtual network peering connections should have gateway transit carefully configured to prevent unintended cross-network traffic."

  sql = <<-EOQ
    select
      p.id as resource,
      case
        when p.allow_gateway_transit = true then 'alarm'
        else 'ok'
      end as status,
      case
        when p.allow_gateway_transit = true then p.name || ' allows gateway transit.'
        else p.name || ' restricts gateway transit.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_virtual_network_peering p;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Network"
  })
} 