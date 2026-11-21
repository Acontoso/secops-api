variable "name" {
  type        = string
  description = "Lambda function name."
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,64}$", var.name))
    error_message = "Use a valid Lambda function name of at most 64 characters."
  }
}

variable "image_uri" {
  type        = string
  description = "Immutable ECR image digest URI."
  validation {
    condition     = can(regex("^[0-9]{12}\\.dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com(\\.cn)?/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$", var.image_uri))
    error_message = "Use an ECR image URI pinned to a lowercase sha256 digest."
  }
}

variable "architecture" {
  type        = string
  description = "Image CPU architecture."
  default     = "x86_64"
  validation {
    condition     = contains(["x86_64", "arm64"], var.architecture)
    error_message = "Architecture must be x86_64 or arm64."
  }
}

variable "memory_size" {
  type        = number
  description = "Memory allocation in MB."
  default     = 512
  validation {
    condition     = var.memory_size >= 128 && var.memory_size <= 10240 && floor(var.memory_size) == var.memory_size
    error_message = "Memory must be an integer between 128 and 10240."
  }
}

variable "timeout" {
  type        = number
  description = "Timeout in seconds."
  default     = 30
  validation {
    condition     = var.timeout >= 1 && var.timeout <= 900 && floor(var.timeout) == var.timeout
    error_message = "Timeout must be an integer between 1 and 900."
  }
}

variable "reserved_concurrent_executions" {
  type        = number
  description = "Reserved concurrency; -1 uses the unreserved pool."
  default     = -1
  validation {
    condition     = var.reserved_concurrent_executions >= -1 && floor(var.reserved_concurrent_executions) == var.reserved_concurrent_executions
    error_message = "Reserved concurrency must be an integer at least -1."
  }
}

variable "environment_variables" {
  type        = map(string)
  description = "Non-secret runtime configuration."
  default     = {}
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch log retention in days."
  default     = 30
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "Select a supported finite CloudWatch retention period."
  }
}

variable "tracing_enabled" {
  type        = bool
  description = "Enable X-Ray active tracing."
  default     = true
}

variable "policy_statements" {
  type        = list(object({ sid = string, actions = list(string), resources = list(string) }))
  description = "Explicit application permissions, including KMS publish permissions for encrypted destinations."
  default     = []
  validation {
    condition     = alltrue([for s in var.policy_statements : length(s.actions) > 0 && length(s.resources) > 0 && alltrue([for r in s.resources : r != "*"])])
    error_message = "Policy statements require actions and explicitly scoped resources."
  }
}

variable "failure_notifications_enabled" {
  type        = bool
  description = "Enable failure destination and alarms. Separate from the ARN so a newly created topic can be used in the same plan."
  default     = false
}

variable "failure_topic_arn" {
  type        = string
  description = "Optional SNS asynchronous failure destination and Errors/Throttles alarm topic. Supply KMS permissions separately."
  default     = null
  validation {
    condition     = var.failure_topic_arn == null ? true : can(regex("^arn:[^:]+:sns:[^:]+:[0-9]{12}:[^:]+$", var.failure_topic_arn))
    error_message = "Failure destination must be an SNS topic ARN."
  }
}

variable "tags" {
  type        = map(string)
  description = "Resource tags."
  default     = {}
}

