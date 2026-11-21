variable "name" {
  type        = string
  description = "Table name."
  validation {
    condition     = length(var.name) >= 3 && length(var.name) <= 255
    error_message = "Table name must contain 3 to 255 characters."
  }
}

variable "hash_key" {
  type        = string
  description = "Partition key attribute."
}

variable "range_key" {
  type        = string
  description = "Optional sort key attribute."
  default     = null
}

variable "attributes" {
  type        = map(string)
  description = "Only table and index key attributes, mapped to S, N or B."
}

variable "global_secondary_indexes" {
  type        = list(object({ name = string, hash_key = string, range_key = optional(string), projection_type = string }))
  description = "Global secondary indexes; ALL and KEYS_ONLY projections are supported."
  default     = []
}

variable "deletion_protection_enabled" {
  type        = bool
  description = "Protect the table against accidental deletion."
  default     = true
}

variable "point_in_time_recovery_enabled" {
  type        = bool
  description = "Enable continuous backup."
  default     = true
}

variable "ttl_attribute" {
  type        = string
  description = "Optional TTL attribute; the application must write epoch seconds to it."
  default     = null
}

variable "kms_key_arn" {
  type        = string
  description = "Optional customer-managed encryption key; null uses AWS-owned encryption."
  default     = null
}

variable "tags" {
  type        = map(string)
  description = "Resource tags."
  default     = {}
}
