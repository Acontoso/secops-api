locals {
  tags = merge(
    {
      "env"        = "${var.environment}"
      "terraform"  = "true"
      "bu"         = "security"
      "RepoUrl"    = "${var.source_code_repo_url}"
      "service"    = "soar-api"
      "owner"      = "patrick-robertson"
      "author"     = "alex skoro"
      "costcentre" = "${var.cost_centre}"
    }
  )
  aws_region = "ap-southeast-2"
}

data "aws_kms_key" "ssm_kms_alias" {
  key_id = "alias/cmk-ssm"
}

module "sns" {
  source         = "./modules/sns"
  sns_topic_name = var.sns_topic_name
  tags           = local.tags
}

module "ssm_parameters" {
  source     = "./modules/ssm"
  kms_key_id = data.aws_kms_key.ssm_kms_alias.id
  tags       = local.tags

  parameters = {
    anomali_user = {
      name        = "/soar-api/anomali_user"
      description = "Anomali username for API integration"
      value       = var.enc_string_anomali_user
    }

    anomali_api = {
      name        = "/soar-api/anomali_api"
      description = "Anomali API key for integration"
      value       = var.enc_string_anomali_api
    }

    ipabuse_db = {
      name        = "/soar-api/ipabuse_db"
      description = "IPAbuse DB API Key"
      value       = var.enc_string_ipabuse_db
    }

    zscaler_client_id = {
      name        = "/soar-api/zscaler_client_id"
      description = "Zscaler Client ID for API integration"
      value       = var.enc_zscaler_client_id
    }

    zscaler_client_secret = {
      name        = "/soar-api/zscaler_client_secret"
      description = "Zscaler Client Secret for API integration"
      value       = var.enc_zscaler_client_secret
    }

    recorded_future_api = {
      name        = "/soar-api/recorded_future_api"
      description = "Recorded Future API key for integration"
      value       = var.enc_recorded_future_api
    }

    cf_is_token = {
      name        = "/soar-api/Instantscripts"
      description = "Cloudflare IS API Token"
      value       = var.enc_cf_api_is_token
    }

    cf_myapidev_token = {
      name        = "/soar-api/MyAPIDev"
      description = "Cloudflare MyAPI Dev Token"
      value       = var.enc_cf_api_myapidev_token
    }

    cf_myapiprod_token = {
      name        = "/soar-api/MyAPIProd"
      description = "Cloudflare MyAPI Prod Token"
      value       = var.enc_cf_api_myapiprod_token
    }

    cf_madev_token = {
      name        = "/soar-api/MADev"
      description = "Cloudflare MA Dev Token"
      value       = var.enc_cf_api_madev_token
    }

    cf_maprod_token = {
      name        = "/soar-api/MAProd"
      description = "Cloudflare MA Prod Token"
      value       = var.enc_cf_api_maprod_token
    }

    cf_pricelinedev_token = {
      name        = "/soar-api/PricelineDev"
      description = "Cloudflare Priceline Dev Token"
      value       = var.enc_cf_api_pricelinedev_token
    }

    cf_pricelineprod_token = {
      name        = "/soar-api/PricelineProd"
      description = "Cloudflare Priceline Prod Token"
      value       = var.enc_cf_api_pricelineprod_token
    }

    cf_sisudev_token = {
      name        = "/soar-api/SiSUDev"
      description = "Cloudflare SISU Dev Token"
      value       = var.enc_cf_api_sisudev_token
    }

    cf_sisuprod_token = {
      name        = "/soar-api/SiSUProd"
      description = "Cloudflare SISU Prod Token"
      value       = var.enc_cf_api_sisuprod_token
    }
  }
}

module "cognito" {
  source                  = "./modules/cognito"
  tags                    = local.tags
  cognito_oidc_userpool   = var.cognito_oidc_userpool
  cognito_domain_name     = var.cognito_domain_name
  cognito_oidc_client_app = var.cognito_oidc_client_app
  identity_pool_name      = var.identity_pool_name
}

module "dynamodb" {
  source                       = "./modules/dynamodb"
  tags                         = local.tags
  dynamodb_table_name_ioc      = var.dynamodb_table_name_ioc
  dynamodb_primary_key_ioc     = var.dynamodb_primary_key_ioc
  dynamodb_sort_key_ioc        = var.dynamodb_sort_key_ioc
  dynamodb_table_name_actions  = var.dynamodb_table_name_actions
  dynamodb_primary_key_actions = var.dynamodb_primary_key_actions
  dynamodb_sort_key_actions    = var.dynamodb_sort_key_actions
}

module "lambda" {
  source                       = "./modules/lambda"
  tags                         = local.tags
  lambda_function_name         = var.lambda_function_name
  runtime                      = var.runtime
  handler                      = var.handler
  memory_size                  = var.memory_size
  timeout                      = var.timeout
  description                  = var.description
  sns_topic_arn                = module.sns.sns_arn
  s3_bucket_name               = var.s3_bucket_name
  ms_tenant_id                 = var.ms_tenant_id
  identity_pool_id             = var.identity_pool_id
  identity_pool_login          = var.identity_pool_login
  cognito_identity_pool_arn    = module.cognito.cognito_identity_pool_arn
  dynamodb_table_name_ioc      = var.dynamodb_table_name_ioc
  dynamodb_primary_key_ioc     = var.dynamodb_primary_key_ioc
  dynamodb_sort_key_ioc        = var.dynamodb_sort_key_ioc
  dynamodb_table_name_actions  = var.dynamodb_table_name_actions
  dynamodb_primary_key_actions = var.dynamodb_primary_key_actions
  dynamodb_sort_key_actions    = var.dynamodb_sort_key_actions
  dynamodb_table_arn_ioc       = module.dynamodb.ioc_table_arn
  dynamodb_table_arn_actions   = module.dynamodb.actions_table_arn
}

module "apigateway" {
  source                        = "./modules/apigateway"
  tags                          = local.tags
  api_gateway_name              = var.api_gateway_name
  api_rate_limit                = var.api_rate_limit
  api_burst_limit               = var.api_burst_limit
  api_gateway_usage_plan_name   = var.api_gateway_usage_plan_name
  aws_lambda_function_name      = module.lambda.lambda_function_name
  stage_name_api_gateway        = var.stage_name_api_gateway
  apigw_cognito_authorizer_name = var.apigw_cognito_authorizer_name
  cognito_user_pool_arn         = module.cognito.aws_cognito_user_pool_arn
  aws_lambda_function_arn       = module.lambda.lambda_function_arn
}

module "bedrockgateway" {
  source                      = "./modules/bedrockgateway"
  tags                        = local.tags
  gateway_name                = var.gateway_name
  gateway_description         = var.gateway_description
  authorization_type          = var.authorization_type
  tenant_id                   = var.tenant_id
  audience_values             = var.audience_values
  arn_oauth_outbound_provider = var.arn_oauth_outbound_provider
}
