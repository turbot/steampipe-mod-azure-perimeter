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
    control.cosmosdb_account_cors_prohibit_public_access
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
    control.storage_account_prohibit_blob_public_access,
    control.storage_container_prohibit_public_access,
    control.kubernetes_cluster_prohibit_public_access
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "storage_account_prohibit_blob_public_access" {
  title       = "Storage accounts should prohibit blob public access"
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
      azure_storage_account a;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Storage"
  })
}

control "storage_container_prohibit_public_access" {
  title       = "Storage containers of blob storage service should prohibit public access"
  description = "Storage containers of blob storage service should have their public access level set to 'None' to prevent unauthorized access."

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
      azure_storage_container c;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Storage"
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
      azure_kubernetes_cluster c;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/AKS"
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
