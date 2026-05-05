variable "tags" {
  type        = map(string)
  description = "Tags to apply to the gateway"
}

variable "api_gateway_name" {
  type        = string
  description = "Name of the API Gateway"
}

variable "stage_name_api_gateway" {
  type        = string
  description = "Name of the API Gateway stage - Single stage deployment"
}

variable "api_gateway_usage_plan_name" {
  type        = string
  description = "Name of the API Gateway usage plan"
}

variable "api_burst_limit" {
  type        = number
  description = "Burst limit for API Gateway usage plan"
}

variable "api_rate_limit" {
  type        = number
  description = "Rate limit for API Gateway usage plan"
}

variable "apigw_cognito_authorizer_name" {
  type        = string
  description = "Name of the API Gateway Cognito Authorizer"
}

variable "aws_lambda_function_name" {
  type        = string
  description = "Name of the AWS Lambda function"
}

variable "aws_lambda_function_arn" {
  type        = string
  description = "ARN of the AWS Lambda function"
}

variable "cognito_user_pool_arn" {
  type        = string
  description = "ARN of the Cognito User Pool"
}
