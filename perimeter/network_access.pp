benchmark "network_access" {
  title         = "Network Access"
  description   = "A network is essential to secure the network traffic and the cloud's environment from being exploited by unauthorized consumers. Network access controls help protect Azure resources from malicious or unauthorized traffic."
  documentation = file("./perimeter/docs/network_access.md")
  children = [
    benchmark.public_ips,
    benchmark.public_network_access,
    benchmark.security_group_access
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
    control.container_registry_restrict_public_network_access,
    control.cosmos_db_account_restrict_public_network_access,
    control.sql_server_restrict_public_network_access,
    control.storage_account_restrict_public_network_access
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "sql_server_restrict_public_network_access" {
  title       = "SQL servers should restrict public network access"
  description = "Azure SQL servers should be configured to restrict public network access through firewall rules, virtual network rules, private endpoints, or by disabling public network access entirely."

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

benchmark "security_group_access" {
  title         = "Security Group Access"
  description   = "Network security groups should be configured to protect Azure resources from unwanted network access."
  documentation = file("./perimeter/docs/security_group_access.md")
  children = [
    control.network_security_group_restrict_ingress_common_ports_all,
    control.network_security_group_restrict_ingress_all_ports_tcp_udp_from_internet
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
        distinct nsg.name sg_name
      from
        azure_network_security_group nsg,
        jsonb_array_elements(security_rules) sg,
        jsonb_array_elements_text(sg -> 'properties' -> 'destinationPortRanges' || (sg -> 'properties' -> 'destinationPortRange') :: jsonb) dport,
        jsonb_array_elements_text(sg -> 'properties' -> 'sourceAddressPrefixes' || (sg -> 'properties' -> 'sourceAddressPrefix') :: jsonb) sip
      where
        sg -> 'properties' ->> 'access' = 'Allow'
        and sg -> 'properties' ->> 'direction' = 'Inbound'
        and sip in ('*', '0.0.0.0', '0.0.0.0/0', 'Internet', 'any', '<nw>/0', '/0')
        and (
          dport in ('20', '21', '22', '23', '25', '110', '135', '143', '445', '1433', '1434', '3306', '3389', '4333', '5432', '5500', '5601', '8080', '9200', '9300')
          or (
            dport like '%-%'
            and (
              (
                split_part(dport, '-', 1) :: integer <= 20
                and split_part(dport, '-', 2) :: integer >= 20
              )
              or (
                split_part(dport, '-', 1) :: integer <= 21
                and split_part(dport, '-', 2) :: integer >= 21
              )
              or (
                split_part(dport, '-', 1) :: integer <= 22
                and split_part(dport, '-', 2) :: integer >= 22
              )
              or (
                split_part(dport, '-', 1) :: integer <= 23
                and split_part(dport, '-', 2) :: integer >= 23
              )
              or (
                split_part(dport, '-', 1) :: integer <= 25
                and split_part(dport, '-', 2) :: integer >= 25
              )
              or (
                split_part(dport, '-', 1) :: integer <= 110
                and split_part(dport, '-', 2) :: integer >= 110
              )
              or (
                split_part(dport, '-', 1) :: integer <= 135
                and split_part(dport, '-', 2) :: integer >= 135
              )
              or (
                split_part(dport, '-', 1) :: integer <= 143
                and split_part(dport, '-', 2) :: integer >= 143
              )
              or (
                split_part(dport, '-', 1) :: integer <= 445
                and split_part(dport, '-', 2) :: integer >= 445
              )
              or (
                split_part(dport, '-', 1) :: integer <= 1433
                and split_part(dport, '-', 2) :: integer >= 1433
              )
              or (
                split_part(dport, '-', 1) :: integer <= 1434
                and split_part(dport, '-', 2) :: integer >= 1434
              )
              or (
                split_part(dport, '-', 1) :: integer <= 3306
                and split_part(dport, '-', 2) :: integer >= 3306
              )
              or (
                split_part(dport, '-', 1) :: integer <= 3389
                and split_part(dport, '-', 2) :: integer >= 3389
              )
              or (
                split_part(dport, '-', 1) :: integer <= 4333
                and split_part(dport, '-', 2) :: integer >= 4333
              )
              or (
                split_part(dport, '-', 1) :: integer <= 5432
                and split_part(dport, '-', 2) :: integer >= 5432
              )
              or (
                split_part(dport, '-', 1) :: integer <= 5500
                and split_part(dport, '-', 2) :: integer >= 5500
              )
              or (
                split_part(dport, '-', 1) :: integer <= 5601
                and split_part(dport, '-', 2) :: integer >= 5601
              )
              or (
                split_part(dport, '-', 1) :: integer <= 8080
                and split_part(dport, '-', 2) :: integer >= 8080
              )
              or (
                split_part(dport, '-', 1) :: integer <= 9200
                and split_part(dport, '-', 2) :: integer >= 9200
              )
              or (
                split_part(dport, '-', 1) :: integer <= 9300
                and split_part(dport, '-', 2) :: integer >= 9300
              )
            )
          )
        )
    )
    select
      nsg.id as resource,
      case
        when cpr.sg_name is null then 'ok'
        else 'alarm'
      end as status,
      case
        when cpr.sg_name is null then nsg.name || ' restricts access to common ports from the internet.'
        else nsg.name || ' allows unrestricted access to common ports from the internet.'
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "nsg.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "nsg.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      azure_network_security_group nsg
      left join common_ports_rules cpr on cpr.sg_name = nsg.name,
      azure_subscription sub
    where
      sub.subscription_id = nsg.subscription_id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Network"
  })
}

control "network_security_group_restrict_ingress_all_ports_tcp_udp_from_internet" {
  title       = "Network security groups should not allow TCP/UDP access to all ports (*) from the internet"
  description = "Azure network security groups should not allow unrestricted TCP/UDP access from the internet to all ports (*). Rules that permit TCP or UDP access to all ports create an extremely broad attack surface."

  sql = <<-EOQ
    with all_ports_rules as (
      select
        distinct nsg.name sg_name
      from
        azure_network_security_group nsg,
        jsonb_array_elements(security_rules) sg,
        jsonb_array_elements_text(sg -> 'properties' -> 'destinationPortRanges' || (sg -> 'properties' -> 'destinationPortRange') :: jsonb) dport,
        jsonb_array_elements_text(sg -> 'properties' -> 'sourceAddressPrefixes' || (sg -> 'properties' -> 'sourceAddressPrefix') :: jsonb) sip
      where
        sg -> 'properties' ->> 'access' = 'Allow'
        and sg -> 'properties' ->> 'direction' = 'Inbound'
        and sg -> 'properties' ->> 'protocol' in ('TCP', 'UDP')
        and sip in ('*', '0.0.0.0', '0.0.0.0/0', 'Internet', 'any', '<nw>/0', '/0')
        and dport = '*'
    )
    select
      nsg.id as resource,
      case
        when apr.sg_name is null then 'ok'
        else 'alarm'
      end as status,
      case
        when apr.sg_name is null then nsg.name || ' restricts TCP/UDP access to all ports from the internet.'
        else nsg.name || ' allows unrestricted TCP/UDP access to all ports (*) from the internet.'
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "nsg.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "nsg.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      azure_network_security_group nsg
      left join all_ports_rules apr on apr.sg_name = nsg.name,
      azure_subscription sub
    where
      sub.subscription_id = nsg.subscription_id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Network"
  })
}

benchmark "public_ips" {
  title         = "Public IPs"
  description   = "Public IP addresses in Azure should be carefully managed to reduce the attack surface of your resources."
  documentation = file("./perimeter/docs/public_ips.md")
  children = [
    control.compute_vm_no_public_ip,
    control.network_interface_not_attached_to_public_ip
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "compute_vm_no_public_ip" {
  title       = "Compute Virtual machines should not have a public IP address"
  description = "Azure compute virtual machines should not have public IP addresses directly assigned to them to reduce exposure to internet-based attacks."

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
  title       = "Network interfaces should not have public IP addresses"
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
