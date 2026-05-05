variable "parameters" {
  description = "Map of SSM SecureString parameters to create"
  type = map(object({
    name        = string
    description = string
    value       = string
  }))
}

variable "kms_key_id" {
  description = "KMS key ID used to encrypt SSM parameters"
  type        = string
}

variable "tags" {
  description = "Tags to apply to all SSM parameters"
  type        = map(string)
  default     = {}
}
