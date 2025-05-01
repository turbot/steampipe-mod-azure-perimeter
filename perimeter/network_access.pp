benchmark "network_access" {
  title         = "Network Access"
  description   = "A network is essential to secure the network traffic and the cloud's environment from being exploited by unauthorized consumers. Network access controls help protect Azure resources from malicious or unauthorized traffic."
  documentation = file("./perimeter/docs/network_access.md")
  children = [
    benchmark.network_access_general,
    benchmark.network_access_security_groups,
    benchmark.network_access_public_ips
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "network_access_general" {
  title         = "Network General Access"
  description   = "Azure resources should implement proper network controls to protect against unauthorized network access."
  documentation = file("./perimeter/docs/network_access_general.md")
  children = [
    control.vnet_peering_restrict_cross_tenant_access,
    control.network_watcher_enabled
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "vnet_peering_restrict_cross_tenant_access" {
  title       = "Virtual network peering should restrict cross-tenant access"
  description = "Azure virtual network peering connections should be limited to within the same tenant to prevent unauthorized cross-tenant network access."

  sql = <<-EOQ
    select
      p.id as resource,
      case
        when p.remote_virtual_network_id is null then 'skip'
        when vn.tenant_id = split_part(p.remote_virtual_network_id, '/', extract(array_length(regexp_split_to_array(p.remote_virtual_network_id, '/'), 1) - 4)::int) then 'ok'
        else 'alarm'
      end as status,
      case
        when p.remote_virtual_network_id is null then p.name || ' has no remote virtual network.'
        when vn.tenant_id = split_part(p.remote_virtual_network_id, '/', extract(array_length(regexp_split_to_array(p.remote_virtual_network_id, '/'), 1) - 4)::int) then p.name || ' is peered within the same tenant.'
        else p.name || ' is peered with a virtual network in a different tenant.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_virtual_network_peering p
      join azure_virtual_network vn on p.virtual_network_id = vn.id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Network"
  })
}

control "network_watcher_enabled" {
  title       = "Network Watcher should be enabled for all regions"
  description = "Azure Network Watcher should be enabled for all regions where you have virtual networks to monitor and diagnose network issues."

  sql = <<-EOQ
    with regions_with_vnets as (
      select distinct
        region
      from
        azure_virtual_network
    ),
    regions_with_watchers as (
      select distinct
        region
      from
        azure_network_watcher
    )
    select
      r.region as resource,
      case
        when w.region is null then 'alarm'
        else 'ok'
      end as status,
      case
        when w.region is null then 'Network Watcher not enabled in region ' || r.region || '.'
        else 'Network Watcher enabled in region ' || r.region || '.'
      end as reason
      ${local.common_dimensions_sql}
    from
      regions_with_vnets r
      left join regions_with_watchers w on r.region = w.region;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Network"
  })
}

benchmark "network_access_security_groups" {
  title         = "Security Group Access"
  description   = "Network security groups should be configured to protect Azure resources from unwanted network access."
  documentation = file("./perimeter/docs/network_access_security_groups.md")
  children = [
    control.nsg_subnet_attached,
    control.nsg_rule_rdp_access_restricted
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "nsg_subnet_attached" {
  title       = "All subnets should be protected by a network security group"
  description = "Azure subnets should have a network security group (NSG) attached to control network traffic and implement security boundaries."

  sql = <<-EOQ
    select
      s.id as resource,
      case
        when s.network_security_group_id is null then 'alarm'
        else 'ok'
      end as status,
      case
        when s.network_security_group_id is null then s.name || ' has no network security group attached.'
        else s.name || ' has network security group attached.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_subnet s;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Network"
  })
}

control "nsg_rule_rdp_access_restricted" {
  title       = "Network security groups should restrict RDP access from the internet"
  description = "Azure network security groups should not allow unrestricted RDP (port 3389) access from the internet to reduce the risk of brute force attacks."

  sql = <<-EOQ
    with rdp_security_rules as (
      select
        id,
        name,
        security_rules
      from
        azure_network_security_group
      where
        jsonb_typeof(security_rules) = 'array'
    ),
    allow_rdp_rules as (
      select
        id,
        name,
        jsonb_array_elements(security_rules) as rule
      from
        rdp_security_rules
      where
        jsonb_typeof(security_rules) = 'array'
        and jsonb_array_length(security_rules) > 0
    )
    select
      id as resource,
      case
        when rule -> 'properties' ->> 'access' = 'Allow'
          and rule -> 'properties' ->> 'direction' = 'Inbound'
          and (
            rule -> 'properties' ->> 'destinationPortRange' = '3389'
            or rule -> 'properties' ->> 'destinationPortRange' = '*'
            or (
              rule -> 'properties' ->> 'destinationPortRange' is null
              and (
                rule -> 'properties' -> 'destinationPortRanges' @> '["3389"]'
                or rule -> 'properties' -> 'destinationPortRanges' @> '["*"]'
              )
            )
          )
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
            rule -> 'properties' ->> 'destinationPortRange' = '3389'
            or rule -> 'properties' ->> 'destinationPortRange' = '*'
            or (
              rule -> 'properties' ->> 'destinationPortRange' is null
              and (
                rule -> 'properties' -> 'destinationPortRanges' @> '["3389"]'
                or rule -> 'properties' -> 'destinationPortRanges' @> '["*"]'
              )
            )
          )
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
        then name || ' allows unrestricted RDP access from the internet with rule: ' || (rule ->> 'name')
        else name || ' restricts RDP access from the internet.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      allow_rdp_rules;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Network"
  })
}

benchmark "network_access_public_ips" {
  title         = "Public IPs"
  description   = "Public IP addresses in Azure should be carefully managed to reduce the attack surface of your resources."
  documentation = file("./perimeter/docs/network_access_public_ips.md")
  children = [
    control.public_ip_restrict_usage,
    control.public_ip_restrict_dynamic_addresses
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "public_ip_restrict_usage" {
  title       = "Public IP addresses should be restricted in usage"
  description = "Azure resources should limit the use of public IP addresses to only those that truly require internet connectivity. Minimize public IP usage to reduce your attack surface."

  sql = <<-EOQ
    select
      ip.id as resource,
      case
        when ip.ip_address is not null then 'alarm'
        else 'ok'
      end as status,
      case
        when ip.ip_address is not null then ip.name || ' has a public IP address: ' || ip.ip_address
        else ip.name || ' does not have a public IP address.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_public_ip ip;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Network"
  })
}

control "public_ip_restrict_dynamic_addresses" {
  title       = "Public IP addresses should use static allocation method"
  description = "Azure public IP addresses should be configured with static allocation to ensure consistent addressing for security configurations like firewall rules."

  sql = <<-EOQ
    select
      ip.id as resource,
      case
        when ip.public_ip_allocation_method = 'Dynamic' then 'alarm'
        else 'ok'
      end as status,
      case
        when ip.public_ip_allocation_method = 'Dynamic' then ip.name || ' uses dynamic IP allocation.'
        else ip.name || ' uses static IP allocation.'
      end as reason
      ${local.tag_dimensions_sql}
      ${local.common_dimensions_sql}
    from
      azure_public_ip ip;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Network"
  })
} 