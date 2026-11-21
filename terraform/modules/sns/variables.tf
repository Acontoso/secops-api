variable "name" {
  type        = string
  description = "SNS topic name."
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,256}$", var.name))
    error_message = "Use a valid standard SNS topic name."
  }
}

variable "kms_key_arn" {
  type        = string
  description = "Customer-managed KMS key ARN. Its policy must authorize publishing services, including CloudWatch alarms, and Lambda publishers."
  validation {
    condition     = can(regex("^arn:[^:]+:kms:[^:]+:[0-9]{12}:key/.+$", var.kms_key_arn))
    error_message = "Supply a KMS key ARN."
  }
}

variable "alarm_source_arn_pattern" {
  type        = string
  description = "ArnLike pattern of CloudWatch alarm ARNs allowed to publish. The module's topic policy is its sole owner."
  validation {
    condition     = can(regex("^arn:[^:]*:cloudwatch:[^:]*:[0-9]{12}:alarm:.+$", var.alarm_source_arn_pattern))
    error_message = "Supply the CloudWatch alarm ARN pattern allowed to publish to this topic."
  }
}

variable "subscriptions" {
  type        = map(object({ protocol = string, endpoint = string }))
  description = "Explicit subscriptions; email subscriptions require recipient confirmation."
  default     = {}
  validation {
    condition     = alltrue([for s in values(var.subscriptions) : contains(["http", "https", "email", "email-json", "sms", "sqs", "application", "lambda", "firehose"], s.protocol) && length(trimspace(s.endpoint)) > 0])
    error_message = "Subscriptions need a supported protocol and nonempty endpoint."
  }
}

variable "tags" {
  type        = map(string)
  description = "Resource tags."
  default     = {}
}

