benchmark "network_access" {
  title         = "Network Access"
  description   = "A network is essential to secure the network traffic and the cloud's environment from being exploited by unauthorized consumers. Network access controls help protect Azure resources from malicious or unauthorized traffic."
  documentation = file("./perimeter/docs/network_access.md")
  children = [
    benchmark.public_network_access,
    benchmark.network_access_public_ips,
    benchmark.network_access_security_groups
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "public_network_access" {
  title         = "Public Network Access"
  description   = "Azure resources should implement proper network controls to protect against unauthorized network access."
  documentation = file("./perimeter/docs/public_network_access.md")
  children = [
    control.sql_server_restrict_public_network_access,
    control.storage_account_restrict_public_network_access,
    control.cosmos_db_account_restrict_public_network_access,
    control.container_registry_restrict_public_network_access
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "sql_server_restrict_public_network_access" {
  title       = "SQL server should restrict public network access"
  description = "Azure SQL server should be configured to restrict public network access through firewall rules, virtual network rules, private endpoints, or by disabling public network access entirely."

  sql = <<-EOQ
    select
      s.id as resource,
    case
      when public_network_access = 'Disabled' then 'ok'
      else 'alarm'
    end as status,
    case
      when public_network_access = 'Disabled' then s.name || ' has public network access disabled.'
      else s.name || ' has public network access enabled.'
    end as reason
    ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "s.")}
    ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "s.")}
    ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
  from
    azure_sql_server s,
    azure_subscription sub
  where
    sub.subscription_id = s.subscription_id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/SQL"
  })
}

control "storage_account_restrict_public_network_access" {
  title       = "Storage accounts should restrict public network access"
  description = "Azure Storage accounts should be configured to restrict public network access through virtual network rules."

  sql = <<-EOQ
    select
      sa.id as resource,
      case
        when public_network_access = 'Disabled' then 'ok'
        else 'alarm'
      end as status,
      case
        when public_network_access = 'Disabled' then sa.name || ' has public network access disabled.'
        else sa.name || ' has public network access enabled.'
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "sa.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "sa.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      azure_storage_account sa,
      azure_subscription sub
    where
      sub.subscription_id = sa.subscription_id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Storage"
  })
}

control "container_registry_restrict_public_network_access" {
  title       = "Container registries should restrict public network access"
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
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "r.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "r.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      azure_container_registry r,
      azure_subscription sub
    where
      sub.subscription_id = r.subscription_id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/ContainerRegistry"
  })
}

control "cosmos_db_account_restrict_public_network_access" {
  title       = "Cosmos DB accounts should restrict public network access"
  description = "Azure Cosmos DB accounts should be configured to restrict public network access through virtual network rules."

  sql = <<-EOQ
    select
      c.id as resource,
      case
        when public_network_access = 'Disabled' then 'ok'
        else 'alarm'
      end as status,
      case
        when public_network_access = 'Disabled' then c.name || ' has public network access disabled.'
        else c.name || ' has public network access enabled.'
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "c.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "c.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      azure_cosmosdb_account c,
      azure_subscription sub
    where
      sub.subscription_id = c.subscription_id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/CosmosDB"
  })
}

benchmark "network_access_security_groups" {
  title         = "Security Group Access"
  description   = "Network security groups should be configured to protect Azure resources from unwanted network access."
  documentation = file("./perimeter/docs/network_access_security_groups.md")
  children = [
    control.network_security_group_restrict_ingress_common_ports_all
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "network_security_group_restrict_ingress_common_ports_all" {
  title       = "Network security groups should restrict ingress access on common ports from the internet"
  description = "Azure network security groups should not allow unrestricted access from the internet to common ports like 22 (SSH), 3389 (RDP), 1433 (SQL), 3306 (MySQL), 5432 (PostgreSQL), and other sensitive ports."

  sql = <<-EOQ
    with common_ports_rules as (
      select
        id,
        name,
        resource_group,
        _ctx,
        region,
        tags,
        subscription_id,
        count(
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
              and (
                (
                  rule -> 'properties' ->> 'destinationPortRange' in ('20', '22', '21', '3389', '3306', '4333', '23', '25', '445', '110', '135', '143', '1433', '1434', '5432', '5500', '5601', '9200', '9300', '8080')
                )
                or (
                rule -> 'properties' ->> 'destinationPortRange' is null
                and (
                  rule -> 'properties' -> 'destinationPortRanges' ?| array['20', '22', '21', '3389', '3306', '4333', '23', '25', '445', '110', '135', '143', '1433', '1434', '5432', '5500', '5601', '9200', '9300', '8080']
                  )

                )
              )
            then 1
          end
        ) as unrestricted_common_ports_count
      from
        azure_network_security_group,
        jsonb_array_elements(security_rules) as rule
      group by
        id, name, resource_group, _ctx, region, tags, subscription_id
    )
    select
      nsg.id as resource,
      case
        when unrestricted_common_ports_count = 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when unrestricted_common_ports_count = 0 then nsg.name || ' restricts access to common ports from the internet.'
        else nsg.name || ' allows unrestricted access to ' || unrestricted_common_ports_count || ' common port(s) from the internet.'
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "nsg.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "nsg.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      common_ports_rules nsg,
      azure_subscription sub
    where
      sub.subscription_id = nsg.subscription_id;
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
    control.network_public_ip_require_static_allocation,
    control.compute_vm_no_public_ip,
    control.network_interface_not_attached_to_public_ip
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "network_public_ip_require_static_allocation" {
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
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "ip.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "ip.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      azure_public_ip ip,
      azure_subscription sub
    where
      sub.subscription_id = ip.subscription_id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Network"
  })
}

control "compute_vm_no_public_ip" {
  title       = "Virtual machines should not have a public IP address"
  description = "Azure virtual machines should not have public IP addresses directly assigned to them to reduce exposure to internet-based attacks."

  sql = <<-EOQ
    select
      vm.id as resource,
      case
        when jsonb_array_length(vm.public_ips) = 0 or vm.public_ips is null then 'ok'
        else 'alarm'
      end as status,
      case
        when jsonb_array_length(vm.public_ips) = 0 or vm.public_ips is null then vm.name || ' does not have public IP addresses.'
        else vm.name || ' has public IP addresses: ' || array_to_string(array(select jsonb_array_elements_text(vm.public_ips)), ', ')
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "vm.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "vm.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      azure_compute_virtual_machine vm,
      azure_subscription sub
    where
      sub.subscription_id = vm.subscription_id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Compute"
  })
}

control "network_interface_not_attached_to_public_ip" {
  title       = "Network interfaces should not have public IP addresses unless required"
  description = "Azure network interfaces should not be assigned public IP addresses unless explicitly required for the workload to minimize internet exposure."

  sql = <<-EOQ
    with nic_public_ips as (
      select
        ni.id,
        ni.name,
        ni.tags,
        ni.resource_group,
        ni._ctx,
        ni.region,
        ni.subscription_id,
        case
          when jsonb_path_exists(ni.ip_configurations, '$[*].properties.publicIPAddress.id') then 'has_public_ip'
          else 'no_public_ip'
        end as public_ip_status
      from
        azure_network_interface ni
    )
    select
      nip.id as resource,
      case
        when public_ip_status = 'no_public_ip' then 'ok'
        else 'alarm'
      end as status,
      case
        when public_ip_status = 'no_public_ip' then nip.name || ' does not have public IP addresses.'
        else nip.name || ' has public IP addresses assigned.'
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "nip.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "nip.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      nic_public_ips nip,
      azure_subscription sub
    where
      sub.subscription_id = nip.subscription_id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Network"
  })
}
