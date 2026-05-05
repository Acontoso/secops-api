variable "source_code_repo_url" {
  type        = string
  description = "Repository where IaC and Lambda function source code resides"
}

variable "environment" {
  description = "Environment the infrastructure is deployed in"
  type        = string
}

variable "cost_centre" {
  description = "Cost centre to apply the resources too"
  type        = string
}

variable "api_gateway_name" {
  description = "Name of API Gateway"
  type        = string
}

variable "api_burst_limit" {
  description = "Maximum of requests allowed within a few milliseconds, allows temp spike in traffic over the rate limit"
  type        = number
}

variable "api_rate_limit" {
  description = "Maxmium number of requests per second the API can handle"
  type        = number
}

variable "api_gateway_usage_plan_name" {
  description = "Maxmium number of requests per second the API can handle"
  type        = string
}

variable "stage_name_api_gateway" {
  description = "Name of core AWS API gateway stage that is linked to deployment & usage plan"
  type        = string
}

variable "lambda_function_name" {
  type        = string
  description = "Name of lambda function"
}

variable "sns_topic_name" {
  type        = string
  description = "SNS topic name"
}

variable "dynamodb_table_name_ioc" {
  type        = string
  description = "DynamoDB table used by the Lambda"
}

variable "dynamodb_primary_key_ioc" {
  type        = string
  description = "DynamoDB partition key"
}

variable "dynamodb_sort_key_ioc" {
  type        = string
  description = "DynamoDB sort key"
}

variable "dynamodb_table_name_actions" {
  type        = string
  description = "DynamoDB table used by the Lambda for actions"
}

variable "dynamodb_primary_key_actions" {
  type        = string
  description = "DynamoDB partition key for actions"
}

variable "dynamodb_sort_key_actions" {
  type        = string
  description = "DynamoDB sort key for actions"
}

variable "s3_bucket_name" {
  type        = string
  description = "S3 bucket name to store Lambda compiled go code artefacts"
}

variable "runtime" {
  type        = string
  description = "Lambda runtime language and version"
}

variable "handler" {
  type        = string
  description = "Specify file & main entry point of Lambda function"
}

variable "memory_size" {
  type        = string
  description = "Size of memory to allocate Lambda function during runtime"
}

variable "timeout" {
  type        = number
  description = "Lambda function timeout"
}

variable "description" {
  type        = string
  description = "What does this stupid function do"
}

variable "enc_string_anomali_user" {
  type        = string
  description = "Anomali username for API integration"
}

variable "enc_string_anomali_api" {
  type        = string
  description = "Anomali API key for integration"
}

variable "enc_string_ipabuse_db" {
  type        = string
  description = "IPAbuse DB API Key"
}

variable "ms_tenant_id" {
  type        = string
  description = "Microsoft Tenant ID specific to this installation"
}

variable "cognito_oidc_userpool" {
  type        = string
  description = "Name of cognito userpool used to run OIDC service for client credential flow"
}

variable "cognito_oidc_client_app" {
  type        = string
  description = "Client app that represents the consumer service authenticating to soar API"
}

variable "cognito_domain_name" {
  type        = string
  description = "Cognito domain name (sub domain) to create when building out Oauth service"
}

variable "apigw_cognito_authorizer_name" {
  type        = string
  description = "Used to verify the token is legitimate when reaching API gateway"
}

variable "identity_pool_id" {
  type        = string
  description = "Identity Pool ID for OIDC authentication"
}

variable "identity_pool_login" {
  type        = string
  description = "Identity Pool Login for OIDC authentication"
}

variable "enc_zscaler_client_id" {
  type        = string
  description = "Zscaler Client ID for API integration"
}

variable "enc_zscaler_client_secret" {
  type        = string
  description = "Zscaler Client Secret for API integration"
}

variable "enc_recorded_future_api" {
  type        = string
  description = "Recorded Future API key for integration"
}

variable "enc_cf_api_is_token" {
  type        = string
  description = "Cloudflare API token for API integration IS"
}

variable "enc_cf_api_sisudev_token" {
  type        = string
  description = "Cloudflare API token for API integration SISUDev"
}

variable "enc_cf_api_sisuprod_token" {
  type        = string
  description = "Cloudflare API token for API integration SISUProd"
}

variable "enc_cf_api_pricelineprod_token" {
  type        = string
  description = "Cloudflare API token for API integration PricelineProd"
}

variable "enc_cf_api_pricelinedev_token" {
  type        = string
  description = "Cloudflare API token for API integration PricelineDev"
}

variable "enc_cf_api_myapiprod_token" {
  type        = string
  description = "Cloudflare API token for API integration MyAPIProd"
}

variable "enc_cf_api_myapidev_token" {
  type        = string
  description = "Cloudflare API token for API integration MyAPIDev"
}

variable "enc_cf_api_madev_token" {
  type        = string
  description = "Cloudflare API token for API integration MADev"
}

variable "enc_cf_api_maprod_token" {
  type        = string
  description = "Cloudflare API token for API integration MAProd"
}

variable "tenant_id" {
  type        = string
  description = "Microsoft Tenant ID used for authentication to the gateway"
}

variable "audience_values" {
  type        = list(string)
  description = "List of audience values used for authentication to the gateway"
}

variable "gateway_name" {
  type        = string
  description = "Name of the gateway"
}

variable "gateway_description" {
  type        = string
  description = "Description of the gateway"
}

variable "authorization_type" {
  type        = string
  description = "Authorization type used to authenticate to the gateway"
}

variable "arn_oauth_outbound_provider" {
  type        = string
  description = "ARN of the OAuth outbound provider used to authenticate to the gateway"
}

variable "identity_pool_name" {
  type        = string
  description = "Name of the Cognito OIDC identity pool"
}
