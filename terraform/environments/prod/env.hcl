# Nonsecret prod configuration. Fill in the placeholder values, or override any
# of them with the matching TG_* environment variables (used by CI). Never put
# tokens or client secrets in this file.
locals {
  aws_region   = get_env("TG_AWS_REGION", "ap-southeast-2")
  account_id   = get_env("TG_ACCOUNT_ID", "")   # prod account ID, 12 digits
  state_bucket = get_env("TG_STATE_BUCKET", "") # existing versioned state bucket
  state_region = get_env("TG_STATE_REGION", local.aws_region)

  # Existing private ECR repository for the Lambda image.
  ecr_repository_url = get_env("TG_ECR_REPOSITORY_URL", "") # <account>.dkr.ecr.<region>.amazonaws.com/<repo>

  # Existing external keys/identity pool (created outside Terraform).
  ssm_kms_key_arn         = get_env("TG_SSM_KMS_KEY_ARN", "")
  application_kms_key_arn = get_env("TG_APPLICATION_KMS_KEY_ARN", "")
  identity_pool_id        = get_env("TG_IDENTITY_POOL_ID", "")
  identity_pool_login     = get_env("TG_IDENTITY_POOL_LOGIN", "")

  # Optional JSON inputs.
  integration_json  = trimspace(get_env("TG_INTEGRATION_ENVIRONMENT", ""))
  agentcore_json    = trimspace(get_env("TG_AGENTCORE", ""))
  subscription_json = trimspace(get_env("TG_NOTIFICATION_SUBSCRIPTIONS", ""))

  integration_environment    = jsondecode(local.integration_json == "" ? "{}" : local.integration_json)
  agentcore                  = jsondecode(local.agentcore_json == "" ? "null" : local.agentcore_json)
  notification_subscriptions = jsondecode(local.subscription_json == "" ? "{}" : local.subscription_json)
  api_cloudwatch_role_arn    = get_env("TG_API_CLOUDWATCH_ROLE_ARN", "") == "" ? null : get_env("TG_API_CLOUDWATCH_ROLE_ARN")

  # Sizing.
  memory_size                    = 1024
  reserved_concurrent_executions = 25
  log_retention_days             = 90
  api_rate_limit                 = 20
  api_burst_limit                = 40
}
