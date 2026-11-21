variable "name" {
  type        = string
  description = "Repository name."
  validation {
    condition     = can(regex("^[a-z0-9]+([._/-][a-z0-9]+)*$", var.name)) && length(var.name) >= 2 && length(var.name) <= 256
    error_message = "Use a valid lowercase ECR repository name."
  }
}

variable "allowed_account_id" {
  type        = string
  description = "Same AWS account allowed to retrieve Lambda images."
  validation {
    condition     = can(regex("^[0-9]{12}$", var.allowed_account_id))
    error_message = "Account ID must contain exactly 12 digits."
  }
}

variable "tags" {
  type        = map(string)
  description = "Resource tags."
  default     = {}
}

