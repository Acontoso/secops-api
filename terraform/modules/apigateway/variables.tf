variable "name" {
  type        = string
  description = "REST API name."
  validation {
    condition     = length(trimspace(var.name)) > 0
    error_message = "Name cannot be empty."
  }
}

variable "stage_name" {
  type        = string
  description = "REST API stage name."
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,128}$", var.stage_name))
    error_message = "Use a valid API Gateway stage name."
  }
}

variable "lambda_function_name" {
  type        = string
  description = "Target Lambda function name."
}

variable "lambda_invoke_arn" {
  type        = string
  description = "Lambda invoke ARN, not the plain function ARN."
  validation {
    condition     = can(regex(":apigateway:[^:]+:lambda:path/2015-03-31/functions/arn:.*:lambda:.*:function:.+/invocations$", var.lambda_invoke_arn))
    error_message = "Supply the Lambda invoke_arn output."
  }
}

variable "cognito_user_pool_arn" {
  type        = string
  description = "Cognito user pool authorizing access tokens."
}

variable "authorization_scopes" {
  type        = list(string)
  description = "Fully qualified OAuth scopes. At least one is required to enforce access-token authorization."
  validation {
    condition     = length(var.authorization_scopes) > 0 && alltrue([for s in var.authorization_scopes : can(regex("^[^ /]+/[^ ]+$", s))])
    error_message = "Provide at least one fully qualified OAuth scope."
  }
}

variable "rate_limit" {
  type        = number
  description = "Steady requests per second applied to every method."
  default     = 100
  validation {
    condition     = var.rate_limit > 0
    error_message = "Rate limit must be positive."
  }
}

variable "burst_limit" {
  type        = number
  description = "Burst request limit applied to every method."
  default     = 200
  validation {
    condition     = var.burst_limit > 0 && floor(var.burst_limit) == var.burst_limit
    error_message = "Burst limit must be a positive integer."
  }
}

variable "log_retention_days" {
  type        = number
  description = "Access log retention days."
  default     = 30
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "Select a supported finite CloudWatch retention period."
  }
}

variable "tracing_enabled" {
  type        = bool
  description = "Enable X-Ray tracing for the API stage."
  default     = true
}

variable "cloudwatch_role_arn" {
  type        = string
  description = "Null creates the account-wide logging role and API Gateway account setting: use only once per AWS account/region. A supplied ARN means logging is already configured outside this module."
  default     = null
  validation {
    condition     = var.cloudwatch_role_arn == null ? true : can(regex("^arn:[^:]+:iam::[0-9]{12}:role/.+$", var.cloudwatch_role_arn))
    error_message = "Supply an IAM role ARN or null."
  }
}

variable "tags" {
  type        = map(string)
  description = "Resource tags."
  default     = {}
}

