data "aws_partition" "current" {}

locals {
  name         = "${var.project}-${var.environment}"
  partition    = data.aws_partition.current.partition
  ssm_prefix   = "/${var.project}/${var.environment}"
  ssm_arn      = "arn:${local.partition}:ssm:${var.aws_region}:${var.account_id}:parameter${local.ssm_prefix}/*"
  identity_arn = "arn:${local.partition}:cognito-identity:${var.aws_region}:${var.account_id}:identitypool/${var.identity_pool_id}"
  tags = merge(var.tags, {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "Terraform"
  })
  openapi = yamldecode(var.openapi_schema)
}

data "aws_iam_policy_document" "service_key" {
  statement {
    sid       = "EnableAccountIAMPermissions"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${var.account_id}:root"]
    }
  }
  statement {
    sid       = "CloudWatchAlarmNotifications"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:cloudwatch:${var.aws_region}:${var.account_id}:alarm:${local.name}*"]
    }
  }
}

resource "aws_kms_key" "service" {
  description             = "${local.name} data and notification encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.service_key.json
  tags                    = local.tags
}

resource "aws_kms_alias" "service" {
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.service.key_id
}

module "notifications" {
  source                   = "./modules/sns"
  name                     = "${local.name}-notifications"
  alarm_source_arn_pattern = "arn:${local.partition}:cloudwatch:${var.aws_region}:${var.account_id}:alarm:${local.name}-*"
  kms_key_arn              = aws_kms_key.service.arn
  subscriptions            = var.notification_subscriptions
  tags                     = local.tags
}

module "ioc_table" {
  source                         = "./modules/dynamodb"
  name                           = "${local.name}-ioc"
  hash_key                       = "IOC"
  range_key                      = "EnrichmentSource"
  attributes                     = { IOC = "S", EnrichmentSource = "S", IOCType = "S", Date = "S", IncidentID = "S", MaliciousConfidence = "S" }
  deletion_protection_enabled    = var.deletion_protection_enabled
  point_in_time_recovery_enabled = true
  kms_key_arn                    = aws_kms_key.service.arn
  global_secondary_indexes = [
    { name = "IOCTypeDate", hash_key = "IOCType", range_key = "Date", projection_type = "ALL" },
    { name = "IOCTypeConfidence", hash_key = "IOCType", range_key = "MaliciousConfidence", projection_type = "ALL" },
    { name = "IOCTypeIncident", hash_key = "IOCType", range_key = "IncidentID", projection_type = "ALL" }
  ]
  tags = local.tags
}

module "actions_table" {
  source                         = "./modules/dynamodb"
  name                           = "${local.name}-actions"
  hash_key                       = "IOC"
  range_key                      = "Integration"
  attributes                     = { IOC = "S", Integration = "S", IncidentID = "S", Date = "S" }
  deletion_protection_enabled    = var.deletion_protection_enabled
  point_in_time_recovery_enabled = true
  kms_key_arn                    = aws_kms_key.service.arn
  global_secondary_indexes = [
    { name = "IOCIncident", hash_key = "IOC", range_key = "IncidentID", projection_type = "ALL" },
    { name = "IOCDate", hash_key = "IOC", range_key = "Date", projection_type = "ALL" }
  ]
  tags = local.tags
}

module "authorization" {
  source = "./modules/cognito"
  name   = local.name
  domain = "${local.name}-${var.account_id}"
  tags   = local.tags
}

module "function" {
  source                         = "./modules/lambda"
  name                           = local.name
  image_uri                      = var.image_uri
  architecture                   = "x86_64"
  memory_size                    = var.memory_size
  timeout                        = 28
  reserved_concurrent_executions = var.reserved_concurrent_executions
  log_retention_days             = var.log_retention_days
  tracing_enabled                = true
  failure_notifications_enabled  = true
  failure_topic_arn              = module.notifications.topic_arn
  tags                           = local.tags
  environment_variables = merge(var.integration_environment, {
    GIN_MODE                    = "release"
    IOC_TABLE_NAME              = module.ioc_table.name
    IOC_TABLE_HASH_KEY          = "IOC"
    IOC_TABLE_SORT_KEY          = "EnrichmentSource"
    SOAR_ACTIONS_TABLE_NAME     = module.actions_table.name
    SOAR_ACTIONS_TABLE_HASH_KEY = "IOC"
    SOAR_ACTIONS_SORT_KEY       = "Integration"
    IDENTITY_POOL_ID            = var.identity_pool_id
    IDENTITY_POOL_LOGIN         = var.identity_pool_login
    SSM_PARAMETER_PREFIX        = local.ssm_prefix
    COGNITO_USER_POOL_ID        = module.authorization.user_pool_id
    COGNITO_CLIENT_ID           = module.authorization.client_id
    COGNITO_REQUIRED_SCOPE      = module.authorization.authorization_scope
  })
  policy_statements = [
    { sid = "ReadVendorParameters", actions = ["ssm:GetParameter"], resources = [local.ssm_arn] },
    { sid = "DecryptVendorCredentials", actions = ["kms:Decrypt"], resources = distinct([var.ssm_kms_key_arn, var.application_kms_key_arn]) },
    { sid = "UseEncryptedApplicationData", actions = ["kms:Decrypt", "kms:GenerateDataKey"], resources = [aws_kms_key.service.arn] },
    { sid = "PublishNotifications", actions = ["sns:Publish"], resources = [module.notifications.topic_arn] },
    {
      sid       = "ReadWriteApplicationTables", actions = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:BatchGetItem", "dynamodb:BatchWriteItem"],
      resources = [module.ioc_table.arn, "${module.ioc_table.arn}/index/*", module.actions_table.arn, "${module.actions_table.arn}/index/*"]
    },
    { sid = "ExternalDeveloperIdentity", actions = ["cognito-identity:GetOpenIdTokenForDeveloperIdentity"], resources = [local.identity_arn] }
  ]
}

module "api" {
  source                = "./modules/apigateway"
  name                  = local.name
  stage_name            = var.environment
  lambda_function_name  = module.function.function_name
  lambda_invoke_arn     = module.function.invoke_arn
  cognito_user_pool_arn = module.authorization.user_pool_arn
  authorization_scopes  = [module.authorization.authorization_scope]
  rate_limit            = var.api_rate_limit
  burst_limit           = var.api_burst_limit
  log_retention_days    = var.log_retention_days
  tracing_enabled       = true
  cloudwatch_role_arn   = var.api_cloudwatch_role_arn
  tags                  = local.tags
}

module "agentcore" {
  count              = var.agentcore == null ? 0 : 1
  source             = "./modules/bedrockgateway"
  name               = "${local.name}-gateway"
  openapi_schema     = jsonencode(merge(local.openapi, { servers = [{ url = module.api.invoke_url }] }))
  discovery_url      = var.agentcore.discovery_url
  audiences          = var.agentcore.audiences
  oauth_provider_arn = var.agentcore.oauth_provider_arn
  oauth_secret_arn   = var.agentcore.oauth_secret_arn
  oauth_scopes       = [module.authorization.authorization_scope]
  tags               = local.tags
}
