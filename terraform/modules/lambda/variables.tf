variable "lambda_function_name" {
  type        = string
  description = "Name of lambda function"
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
  description = "Description of the Lambda function"
}

variable "sns_topic_arn" {
  type        = string
  description = "ARN of the SNS topic to allow failures to be published from the Lambda function"
}

variable "tags" {
  type        = map(string)
  description = "Tags to apply to the gateway"
}

variable "s3_bucket_name" {
  type        = string
  description = "Name of the S3 bucket to store Lambda code"
}

variable "dynamodb_table_name_ioc" {
  type        = string
  description = "Name of DynamoDB table for IOCs"
}

variable "dynamodb_primary_key_ioc" {
  type        = string
  description = "Primary key of DynamoDB table for IOCs"
}

variable "dynamodb_sort_key_ioc" {
  type        = string
  description = "Sort key of DynamoDB table for IOCs"
}

variable "dynamodb_table_name_actions" {
  type        = string
  description = "Name of DynamoDB table for SOAR actions"
}

variable "dynamodb_primary_key_actions" {
  type        = string
  description = "Primary key of DynamoDB table for SOAR actions"
}

variable "dynamodb_sort_key_actions" {
  type        = string
  description = "Sort key of DynamoDB table for SOAR actions"
}

variable "ms_tenant_id" {
  type        = string
  description = "Microsoft tenant ID for SOAR integration"
}

variable "identity_pool_id" {
  type        = string
  description = "Cognito Identity Pool ID for SOAR integration"
}

variable "identity_pool_login" {
  type        = string
  description = "Cognito Identity Pool login key for SOAR integration"
}

variable "dynamodb_table_arn_ioc" {
  type        = string
  description = "ARN of the DynamoDB table for IOCs"
}

variable "dynamodb_table_arn_actions" {
  type        = string
  description = "ARN of the DynamoDB table for SOAR actions"
}

variable "cognito_identity_pool_arn" {
  type        = string
  description = "ARN of the Cognito Identity Pool"
}
