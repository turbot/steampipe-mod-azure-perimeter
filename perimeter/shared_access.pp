variable "trusted_principal_ids" {
  type        = list(string)
  default     = ["12345678-1234-1234-1234-123456789abc", "87654321-1234-1234-1234-123456789def"]
  description = "A list of trusted principal IDs (users, groups, service principals) that resources can be shared with."
}

variable "trusted_service_principal_ids" {
  type        = list(string)
  default     = ["12345678-abcd-efgh-ijkl-123456789abc", "87654321-abcd-efgh-ijkl-123456789def"]
  description = "A list of trusted service principal IDs that can have elevated role assignments."
}

variable "privileged_roles" {
  type        = list(string)
  default     = ["Owner", "Contributor", "User Access Administrator", "Security Admin", "Global Administrator"]
  description = "A list of privileged role names that should be monitored for trusted assignment."
}

benchmark "shared_access" {
  title         = "Shared Access"
  description   = "Resources should only be shared with trusted entities through Azure Role-Based Access Control (RBAC), policy assignments, or resource policies."
  documentation = file("./perimeter/docs/shared_access.md")
  children = [
    benchmark.rbac_shared_access,
    benchmark.privileged_role_assignments
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
    control.role_assignment_shared_with_trusted_principals,
    control.role_assignment_service_principal_with_trusted_entities,
    control.role_assignment_cross_subscription_shared_with_trusted_subscriptions
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "privileged_role_assignments" {
  title         = "Privileged Role Assignments"
  description   = "Privileged roles like Owner, Contributor, and administrative roles should only be assigned to trusted principals and monitored carefully."
  documentation = file("./perimeter/docs/privileged_role_assignments.md")
  children = [
    control.privileged_role_assignment_with_trusted_principals,
    control.owner_role_assignment_limit_scope,
    control.user_access_administrator_role_assignment_limit_scope
  ]

  tags = merge(local.azure_perimeter_common_tags, {
    type = "Benchmark"
  })
}

control "role_assignment_shared_with_trusted_principals" {
  title       = "Role assignments should only be granted to trusted principals"
  description = "Azure RBAC role assignments should only be granted to principals (users, groups, service principals) that are part of the trusted list to prevent unauthorized access."

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
    ),
    untrusted_assignments as (
      select
        id,
        name,
        scope,
        principal_id,
        principal_type,
        role_name,
        subscription_id,
        _ctx,
        case
          when principal_id = any(($1)::text[]) then false
          else true
        end as is_untrusted
      from
        role_assignments_with_details
    )
    select
      id as resource,
      case
        when is_untrusted then 'alarm'
        else 'ok'
      end as status,
      case
        when is_untrusted then 
          'Role assignment ' || name || ' grants ' || coalesce(role_name, 'Unknown Role') || ' role to untrusted principal ' || principal_id || '.'
        else 
          'Role assignment ' || name || ' grants ' || coalesce(role_name, 'Unknown Role') || ' role to trusted principal ' || principal_id || '.'
      end as reason
      ${local.common_dimensions_subscription_id_sql}
    from
      untrusted_assignments;
  EOQ

  param "trusted_principal_ids" {
    description = "A list of trusted principal IDs."
    default     = var.trusted_principal_ids
  }

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/RBAC"
  })
}
// Service principals are non-human identities in Azure AD
control "role_assignment_service_principal_with_trusted_entities" {
  title       = "Service principal role assignments should only be granted to trusted service principals"
  description = "Azure RBAC role assignments for service principals should only be granted to service principals that are part of the trusted list to prevent unauthorized application access."

  sql = <<-EOQ
    with service_principal_assignments as (
      select
        ra.id,
        ra.name,
        ra.scope,
        ra.principal_id,
        ra.role_definition_id,
        rd.role_name,
        ra.subscription_id,
        ra._ctx
      from
        azure_role_assignment ra
        left join azure_role_definition rd on ra.role_definition_id = rd.id
      where
        ra.principal_type = 'ServicePrincipal'
        and ra.principal_id is not null
    ),
    untrusted_sp_assignments as (
      select
        id,
        name,
        scope,
        principal_id,
        role_name,
        subscription_id,
        _ctx,
        case
          when principal_id = any(($1)::text[]) then false
          else true
        end as is_untrusted
      from
        service_principal_assignments
    )
    select
      id as resource,
      case
        when is_untrusted then 'alarm'
        else 'ok'
      end as status,
      case
        when is_untrusted then 
          'Service principal role assignment ' || name || ' grants ' || coalesce(role_name, 'Unknown Role') || ' role to untrusted service principal ' || principal_id || '.'
        else 
          'Service principal role assignment ' || name || ' grants ' || coalesce(role_name, 'Unknown Role') || ' role to trusted service principal ' || principal_id || '.'
      end as reason
      ${local.common_dimensions_subscription_id_sql}
    from
      untrusted_sp_assignments;
  EOQ

  param "trusted_service_principal_ids" {
    description = "A list of trusted service principal IDs."
    default     = var.trusted_service_principal_ids
  }

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/RBAC"
  })
}

control "role_assignment_cross_subscription_shared_with_trusted_subscriptions" {
  title       = "Cross-subscription role assignments should only be granted to trusted subscriptions"
  description = "Azure RBAC role assignments that grant access across subscription boundaries should only target resources in trusted subscriptions to prevent unauthorized cross-subscription access."

  sql = <<-EOQ
    with cross_subscription_assignments as (
      select
        ra.id,
        ra.name,
        ra.scope,
        ra.principal_id,
        ra.principal_type,
        ra.role_definition_id,
        rd.role_name,
        ra.subscription_id,
        ra._ctx,
        -- Extract subscription ID from scope if it's a cross-subscription assignment
        case 
          when ra.scope ~ '^/subscriptions/[^/]+/' then
            split_part(split_part(ra.scope, '/subscriptions/', 2), '/', 1)
          else ra.subscription_id
        end as target_subscription_id
      from
        azure_role_assignment ra
        left join azure_role_definition rd on ra.role_definition_id = rd.id
      where
        ra.scope ~ '^/subscriptions/[^/]+/'
    ),
    untrusted_cross_sub_assignments as (
      select
        id,
        name,
        scope,
        principal_id,
        principal_type,
        role_name,
        subscription_id,
        target_subscription_id,
        _ctx,
        case
          when target_subscription_id = subscription_id then false -- Same subscription
          when target_subscription_id = any(($1)::text[]) then false -- Trusted subscription
          else true
        end as is_untrusted
      from
        cross_subscription_assignments
      where
        target_subscription_id != subscription_id -- Only cross-subscription assignments
    )
    select
      id as resource,
      case
        when is_untrusted then 'alarm'
        else 'ok'
      end as status,
      case
        when is_untrusted then 
          'Cross-subscription role assignment ' || name || ' grants ' || coalesce(role_name, 'Unknown Role') || ' role to untrusted subscription ' || target_subscription_id || '.'
        else 
          'Cross-subscription role assignment ' || name || ' grants ' || coalesce(role_name, 'Unknown Role') || ' role to trusted subscription ' || target_subscription_id || '.'
      end as reason
      ${local.common_dimensions_subscription_id_sql}
    from
      untrusted_cross_sub_assignments;
  EOQ

  param "trusted_subscriptions" {
    description = "A list of trusted subscription IDs."
    default     = var.trusted_subscriptions
  }

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/RBAC"
  })
}

control "privileged_role_assignment_with_trusted_principals" {
  title       = "Privileged role assignments should only be granted to trusted principals"
  description = "Azure RBAC assignments for privileged roles (Owner, Contributor, User Access Administrator, etc.) should only be granted to trusted principals to prevent unauthorized administrative access."

  sql = <<-EOQ
    with privileged_role_assignments as (
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
        rd.role_name = any(($2)::text[])
        and ra.principal_id is not null
    ),
    untrusted_privileged_assignments as (
      select
        id,
        name,
        scope,
        principal_id,
        principal_type,
        role_name,
        subscription_id,
        _ctx,
        case
          when principal_id = any(($1)::text[]) then false
          else true
        end as is_untrusted
      from
        privileged_role_assignments
    )
    select
      id as resource,
      case
        when is_untrusted then 'alarm'
        else 'ok'
      end as status,
      case
        when is_untrusted then 
          'Privileged role assignment ' || name || ' grants ' || role_name || ' role to untrusted principal ' || principal_id || '.'
        else 
          'Privileged role assignment ' || name || ' grants ' || role_name || ' role to trusted principal ' || principal_id || '.'
      end as reason
      ${local.common_dimensions_subscription_id_sql}
    from
      untrusted_privileged_assignments;
  EOQ

  param "trusted_principal_ids" {
    description = "A list of trusted principal IDs."
    default     = var.trusted_principal_ids
  }

  param "privileged_roles" {
    description = "A list of privileged role names."
    default     = var.privileged_roles
  }

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/RBAC"
  })
}

control "owner_role_assignment_limit_scope" {
  title       = "Owner role assignments should be limited in scope"
  description = "Azure RBAC Owner role assignments should be limited to the minimum necessary scope. Subscription-level Owner assignments should be carefully monitored and justified."

  sql = <<-EOQ
    with owner_role_assignments as (
      select
        ra.id,
        ra.name,
        ra.scope,
        ra.principal_id,
        ra.principal_type,
        ra.role_definition_id,
        rd.role_name,
        ra.subscription_id,
        ra._ctx,
        case
          when ra.scope = '/subscriptions/' || ra.subscription_id then 'subscription'
          when ra.scope ~ '^/subscriptions/[^/]+/resourceGroups/[^/]+$' then 'resource_group'
          when ra.scope ~ '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/' then 'resource'
          else 'other'
        end as scope_type
      from
        azure_role_assignment ra
        left join azure_role_definition rd on ra.role_definition_id = rd.id
      where
        rd.role_name = 'Owner'
        and ra.principal_id is not null
    )
    select
      id as resource,
      case
        when scope_type = 'subscription' then 'alarm'
        when scope_type = 'resource_group' then 'info'
        else 'ok'
      end as status,
      case
        when scope_type = 'subscription' then 
          'Owner role assignment ' || name || ' has subscription-level scope for principal ' || principal_id || '.'
        when scope_type = 'resource_group' then 
          'Owner role assignment ' || name || ' has resource group scope for principal ' || principal_id || '.'
        else 
          'Owner role assignment ' || name || ' has limited scope for principal ' || principal_id || '.'
      end as reason
      ${local.common_dimensions_subscription_id_sql}
    from
      owner_role_assignments;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/RBAC"
  })
}

control "user_access_administrator_role_assignment_limit_scope" {
  title       = "User Access Administrator role assignments should be limited in scope"
  description = "Azure RBAC User Access Administrator role assignments should be limited to the minimum necessary scope. This role can manage access to Azure resources and should be carefully controlled."

  sql = <<-EOQ
    with uaa_role_assignments as (
      select
        ra.id,
        ra.name,
        ra.scope,
        ra.principal_id,
        ra.principal_type,
        ra.role_definition_id,
        rd.role_name,
        ra.subscription_id,
        ra._ctx,
        case
          when ra.scope = '/subscriptions/' || ra.subscription_id then 'subscription'
          when ra.scope ~ '^/subscriptions/[^/]+/resourceGroups/[^/]+$' then 'resource_group'
          when ra.scope ~ '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/' then 'resource'
          else 'other'
        end as scope_type
      from
        azure_role_assignment ra
        left join azure_role_definition rd on ra.role_definition_id = rd.id
      where
        rd.role_name = 'User Access Administrator'
        and ra.principal_id is not null
    )
    select
      id as resource,
      case
        when scope_type = 'subscription' then 'alarm'
        when scope_type = 'resource_group' then 'info'
        else 'ok'
      end as status,
      case
        when scope_type = 'subscription' then 
          'User Access Administrator role assignment ' || name || ' has subscription-level scope for principal ' || principal_id || '.'
        when scope_type = 'resource_group' then 
          'User Access Administrator role assignment ' || name || ' has resource group scope for principal ' || principal_id || '.'
        else 
          'User Access Administrator role assignment ' || name || ' has limited scope for principal ' || principal_id || '.'
      end as reason
      ${local.common_dimensions_subscription_id_sql}
    from
      uaa_role_assignments;
  EOQ

  tags = merge(local.azure_perimeter_common_tags, {
    service = "Azure/RBAC"
  })
} 