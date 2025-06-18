variable "trusted_group_names" {
  type        = list(string)
  default     = ["DevOps", "test-graph"]
  description = "A list of trusted group display names that resources can be shared with."
}

variable "trusted_service_principal_names" {
  type        = list(string)
  default     = ["sp-app1", "sp-app2"]
  description = "A list of trusted service principal display names that resources can be shared with."
}

variable "trusted_user_principal_names" {
  type        = list(string)
  default     = ["user1@domain.com", "user2@domain.com"]
  description = "A list of trusted user principal names (user_principal_name) that resources can be shared with. This is a unique and mandatory field for Azure AD users."
}

benchmark "shared_access" {
  title         = "Shared Access"
  description   = "Resources should only be shared with trusted entities through Azure Role-Based Access Control (RBAC), policy assignments, or resource policies."
  documentation = file("./perimeter/docs/shared_access.md")
  children = [
    benchmark.rbac_shared_access
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "rbac_shared_access" {
  title         = "RBAC Shared Access"
  description   = "Azure Role-Based Access Control (RBAC) helps you manage who has access to Azure resources. Role assignments should only be granted to trusted principals."
  documentation = file("./perimeter/docs/rbac_shared_access.md")
  children = [
    control.role_assignment_shared_with_trusted_users,
    control.role_assignment_shared_with_trusted_groups,
    control.role_assignment_shared_with_trusted_service_principals,
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "role_assignment_shared_with_trusted_users" {
  title       = "Role assignments should only be granted to trusted user principals"
  description = "Azure RBAC role assignments should only be granted to user principals whose user_principal_name is in the trusted list."

  sql = <<-EOQ
    with role_assignments_with_details as (
      select
        ra.id,
        ra.name,
        ra.scope,
        ra.principal_id,
        ra.principal_type,
        ra.role_definition_id,
        rd.role_name,
        ra.subscription_id,
        ra._ctx
      from
        azure_role_assignment ra
        left join azure_role_definition rd on ra.role_definition_id = rd.id
      where
        ra.principal_id is not null
        and ra.principal_type = 'User'
    ),
    role_assignments_with_user_details as (
      select
        ra.id,
        ra.name,
        ra.scope,
        ra.principal_id,
        ra.principal_type,
        ra.role_name,
        ra.subscription_id,
        ra._ctx,
        coalesce(u.user_principal_name, ra.principal_id) as user_principal_name
      from
        role_assignments_with_details ra
        left join azuread_user u on ra.principal_id = u.id
    ),
    untrusted_assignments as (
      select
        *,
        case
          when user_principal_name = any(($1)::text[]) then false
          when user_principal_name is null then true
          else true
        end as is_untrusted
      from
        role_assignments_with_user_details
    )
    select
      ua.id as resource,
      case when is_untrusted then 'alarm' else 'ok' end as status,
      case
        when is_untrusted then 'Role assignment ' || ua.name || ' grants ' || ua.role_name || ' role to untrusted user ' || user_principal_name || ' on scope ' || ua.scope || '.'
        else 'Role assignment ' || ua.name || ' grants ' || ua.role_name || ' role to trusted user ' || user_principal_name || ' on scope ' || ua.scope || '.'
      end as reason
      ${replace(local.common_dimensions_subscription_id_qualifier_sql, "__QUALIFIER__", "ua.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      untrusted_assignments ua,
      azure_subscription sub
    where
      sub.subscription_id = ua.subscription_id;
  EOQ

  param "trusted_user_principal_names" {
    description = "A list of trusted user principal names (user_principal_name)."
    default     = var.trusted_user_principal_names
  }

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/RBAC"
  })
}

control "role_assignment_shared_with_trusted_groups" {
  title       = "Role assignments should only be granted to trusted groups"
  description = "Azure RBAC role assignments should only be granted to groups whose display name is in the trusted list."

  sql = <<-EOQ
    with role_assignments_with_details as (
      select
        ra.id,
        ra.name,
        ra.scope,
        ra.principal_id,
        ra.principal_type,
        ra.role_definition_id,
        rd.role_name,
        ra.subscription_id,
        ra._ctx
      from
        azure_role_assignment ra
        left join azure_role_definition rd on ra.role_definition_id = rd.id
      where
        ra.principal_id is not null
        and ra.principal_type = 'Group'
    ),
    role_assignments_with_group_details as (
      select
        ra.id,
        ra.name,
        ra.scope,
        ra.principal_id,
        ra.principal_type,
        ra.role_name,
        ra.subscription_id,
        ra._ctx,
        coalesce(g.display_name, ra.principal_id) as group_name
      from
        role_assignments_with_details ra
        left join azuread_group g on ra.principal_id = g.id
    ),
    untrusted_assignments as (
      select
        *,
        case
          when group_name = any(($1)::text[]) then false
          when group_name is null then true
          else true
        end as is_untrusted
      from
        role_assignments_with_group_details
    )
    select
      ua.id as resource,
      case when is_untrusted then 'alarm' else 'ok' end as status,
      case
        when is_untrusted then 'Role assignment ' || ua.name || ' grants ' || ua.role_name || ' role to untrusted group ' || group_name || ' on scope ' || ua.scope || '.'
        else 'Role assignment ' || ua.name || ' grants ' || ua.role_name || ' role to trusted group ' || group_name || ' on scope ' || ua.scope || '.'
      end as reason
      ${replace(local.common_dimensions_subscription_id_qualifier_sql, "__QUALIFIER__", "ua.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      untrusted_assignments ua,
      azure_subscription sub
    where
      sub.subscription_id = ua.subscription_id;
  EOQ

  param "trusted_group_names" {
    description = "A list of trusted group display names."
    default     = var.trusted_group_names
  }

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/RBAC"
  })
}

control "role_assignment_shared_with_trusted_service_principals" {
  title       = "Role assignments should only be granted to trusted service principals (by display name)"
  description = "Azure RBAC role assignments should only be granted to service principals whose display name is in the trusted list."

  sql = <<-EOQ
    with role_assignments_with_details as (
      select
        ra.id,
        ra.name,
        ra.scope,
        ra.principal_id,
        ra.principal_type,
        ra.role_definition_id,
        rd.role_name,
        ra.subscription_id,
        ra._ctx
      from
        azure_role_assignment ra
        left join azure_role_definition rd on ra.role_definition_id = rd.id
      where
        ra.principal_id is not null
        and ra.principal_type = 'ServicePrincipal'
    ),
    role_assignments_with_sp_details as (
      select
        ra.id,
        ra.name,
        ra.scope,
        ra.principal_id,
        ra.principal_type,
        ra.role_name,
        ra.subscription_id,
        ra._ctx,
        coalesce(sp.display_name, ra.principal_id) as sp_name
      from
        role_assignments_with_details ra
        left join azuread_service_principal sp on ra.principal_id = sp.id
    ),
    untrusted_assignments as (
      select
        *,
        case
          when sp_name = any(($1)::text[]) then false
          when sp_name is null then true
          else true
        end as is_untrusted
      from
        role_assignments_with_sp_details
    )
    select
      ua.id as resource,
      case when is_untrusted then 'alarm' else 'ok' end as status,
      case
        when is_untrusted then 'Role assignment ' || ua.name || ' grants ' || ua.role_name || ' role to untrusted service principal ' || ua.sp_name || ' on scope ' || ua.scope || '.'
        else 'Role assignment ' || ua.name || ' grants ' || ua.role_name || ' role to trusted service principal ' || ua.sp_name || ' on scope ' || ua.scope || '.'
      end as reason
      ${replace(local.common_dimensions_subscription_id_qualifier_sql, "__QUALIFIER__", "ua.")}
      ${replace(local.common_dimensions_qualifier_subscription_sql, "__QUALIFIER__", "sub.")}
    from
      untrusted_assignments ua,
      azure_subscription sub
    where
      sub.subscription_id = ua.subscription_id;
  EOQ

  param "trusted_service_principal_names" {
    description = "A list of trusted service principal display names."
    default     = var.trusted_service_principal_names
  }

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/RBAC"
  })
}
