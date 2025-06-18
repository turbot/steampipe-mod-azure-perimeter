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

benchmark "resource_cors_public_access" {
  title         = "Resource cors policy public access"
  description   = "Resources should not be publicly accessible through CORS policies."
  documentation = file("./perimeter/docs/resource_cors_public_access.md")
  children = [
    control.cosmosdb_account_cors_prohibit_public_access,
    control.appservice_web_app_cors_prohibit_public_access,
    control.appservice_function_app_cors_prohibit_public_access,
    control.appservice_api_app_cors_prohibit_public_access
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
    control.kubernetes_cluster_private_only,
    control.storage_account_blob_containers_prohibit_public_access,
    control.storage_container_prohibit_public_access
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "storage_account_blob_containers_prohibit_public_access" {
  title       = "Storage account blob containers should prohibit public access"
  description = "Azure Storage accounts should have the 'Allow Blob public access' property set to disabled to prevent unauthorized access."

  sql = <<-EOQ
    select
      a.id as resource,
      case
        when not allow_blob_public_access then 'ok'
        else 'alarm'
      end as status,
      case
        when not allow_blob_public_access then a.name || ' prohibits public access to blobs.'
        else a.name || ' allows public access to blobs.'
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "a.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "a.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      azure_storage_account a,
      azure_subscription sub
    where
      sub.subscription_id = a.subscription_id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Storage"
  })
}

control "storage_container_prohibit_public_access" {
  title       = "Storage containers should prohibit public access"
  description = "Storage containers should have their public access level set to 'None' to prevent unauthorized access."

  sql = <<-EOQ
    select
      c.id as resource,
      case
        when c.public_access = 'None' then 'ok'
        else 'alarm'
      end as status,
      case
        when c.public_access = 'None' then c.name || ' prohibits public access.'
        when c.public_access = 'Blob' then c.name || ' allows public blob access.'
        when c.public_access = 'Container' then c.name || ' allows full public container access.'
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "c.")}
      ${replace(local.common_dimensions_global_qualifier_sql, "__QUALIFIER__", "c.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      azure_storage_container c,
      azure_subscription sub
    where
      sub.subscription_id = c.subscription_id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/Storage"
  })
}

control "kubernetes_cluster_private_only" {
  title       = "AKS clusters should be private only"
  description = "Azure Kubernetes Service (AKS) clusters should have private cluster enabled to restrict worker node from API access for better security and isolation."

  sql = <<-EOQ
    select
      c.id as resource,
      case
        when api_server_access_profile ->> 'enablePrivateCluster' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when api_server_access_profile ->> 'enablePrivateCluster' = 'true' then c.name || ' is private.'
        else c.name || ' is not private.'
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "c.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "c.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      azure_kubernetes_cluster c,
      azure_subscription sub
    where
      sub.subscription_id = c.subscription_id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/AKS"
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
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "c.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "c.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      cors_configured_accounts c,
      azure_subscription sub
    where
      sub.subscription_id = c.subscription_id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/CosmosDB"
  })
}

control "appservice_web_app_cors_prohibit_public_access" {
  title       = "Web App CORS policies should prohibit public access"
  description = "Azure App Service Web App Cross-Origin Resource Sharing (CORS) policies should not allow unrestricted access from any origin that could enable public access."

  sql = <<-EOQ
    select
      a.id as resource,
      case
        when configuration -> 'properties' -> 'cors' -> 'allowedOrigins' @> '["*"]' then 'alarm'
        else 'ok'
      end as status,
      case
        when configuration -> 'properties' -> 'cors' -> 'allowedOrigins' @> '["*"]'
          then a.name || ' CORS allow all domains to access the application.'
        else a.name || ' CORS does not all domains to access the application.'
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "a.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "a.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      azure_app_service_web_app as a,
      azure_subscription as sub
    where
      sub.subscription_id = a.subscription_id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/AppService"
  })
}

control "appservice_function_app_cors_prohibit_public_access" {
  title       = "Function App CORS policies should prohibit public access"
  description = "Azure App Service Function App Cross-Origin Resource Sharing (CORS) policies should not allow unrestricted access from any origin that could enable public access."

  sql = <<-EOQ
    select
      b.id as resource,
      case
        when configuration -> 'properties' -> 'cors' -> 'allowedOrigins' @> '["*"]' then 'alarm'
        else 'ok'
      end as status,
      case
        when configuration -> 'properties' -> 'cors' -> 'allowedOrigins' @> '["*"]'
          then b.name || ' CORS allow all domains to access the application.'
        else b.name || ' CORS does not all domains to access the application.'
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "b.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "b.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      azure_app_service_function_app as b,
      azure_subscription as sub
    where
      sub.subscription_id = b.subscription_id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/AppService"
  })
}

control "appservice_api_app_cors_prohibit_public_access" {
  title       = "API App CORS policies should prohibit public access"
  description = "Azure App Service API App Cross-Origin Resource Sharing (CORS) policies should not allow unrestricted access from any origin that could enable public access."

  sql = <<-EOQ
    with all_api_app as (
      select
        id
      from
        azure_app_service_web_app
      where
        exists (
          select
          from
            unnest(regexp_split_to_array(kind, ',')) elem
          where
            elem like '%api'
      )
    )
    select
      a.id as resource,
      case
        when b.id is null then 'skip'
        when configuration -> 'properties' -> 'cors' -> 'allowedOrigins' @> '["*"]' then 'alarm'
        else 'ok'
      end as status,
      case
        when b.id is null then a.title || ' is ' || a.kind || ' kind.'
        when configuration -> 'properties' -> 'cors' -> 'allowedOrigins' @> '["*"]' then a.name || ' CORS allow all domains to access the application.'
        else a.name || ' CORS does not all domains to access the application.'
      end as reason
      ${replace(local.tag_dimensions_qualifier_sql, "__QUALIFIER__", "a.")}
      ${replace(local.common_dimensions_qualifier_sql, "__QUALIFIER__", "a.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      azure_app_service_web_app as a
      left join all_api_app as b on a.id = b.id,
      azure_subscription as sub
    where
      sub.subscription_id = a.subscription_id;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/AppService"
  })
}
