
terraform_binary              = "terraform"
terraform_version_constraint  = ">= 1.15.6, < 2.0"
terragrunt_version_constraint = "= 1.0.8"

locals {
  env = read_terragrunt_config("${get_original_terragrunt_dir()}/env.hcl")
}

terraform {
  source            = "${get_repo_root()}/terraform"
  exclude_from_copy = ["environments", ".terragrunt-cache", ".terraform", "tests"]
}

# Backend resources already exist. Generating the block does not create or
# modify the bucket. State is separate per environment.
generate "backend" {
  path      = "backend.generated.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<-EOF
    terraform {
      backend "s3" {
        bucket       = "${local.env.locals.state_bucket}"
        key          = "${path_relative_to_include()}/terraform.tfstate"
        region       = "${local.env.locals.state_region}"
        encrypt      = true
        use_lockfile = true
      }
    }
  EOF
}

# The application module declares account_id/aws_region, so the account guard
# is enforced by the module's own validations.
generate "provider" {
  path      = "provider.generated.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<-EOF
    provider "aws" {
      region              = var.aws_region
      allowed_account_ids = [var.account_id]
      default_tags {
        tags = var.tags
      }
    }
  EOF
}

inputs = {
  project                        = "soar-api"
  environment                    = element(reverse(split("/", path_relative_to_include())), 0)
  account_id                     = local.env.locals.account_id
  aws_region                     = local.env.locals.aws_region
  ecr_repository_url             = local.env.locals.ecr_repository_url
  image_uri                      = "${local.env.locals.ecr_repository_url}@${get_env("TG_IMAGE_DIGEST", "")}"
  ssm_kms_key_arn                = local.env.locals.ssm_kms_key_arn
  application_kms_key_arn        = local.env.locals.application_kms_key_arn
  identity_pool_id               = local.env.locals.identity_pool_id
  identity_pool_login            = local.env.locals.identity_pool_login
  integration_environment        = local.env.locals.integration_environment
  agentcore                      = local.env.locals.agentcore
  notification_subscriptions     = local.env.locals.notification_subscriptions
  api_cloudwatch_role_arn        = local.env.locals.api_cloudwatch_role_arn
  memory_size                    = local.env.locals.memory_size
  reserved_concurrent_executions = local.env.locals.reserved_concurrent_executions
  log_retention_days             = local.env.locals.log_retention_days
  api_rate_limit                 = local.env.locals.api_rate_limit
  api_burst_limit                = local.env.locals.api_burst_limit
  openapi_schema                 = file("${get_repo_root()}/openapi.yaml")
  tags = {
    Project     = "soar-api"
    Environment = element(reverse(split("/", path_relative_to_include())), 0)
    ManagedBy   = "Terraform"
  }
}
