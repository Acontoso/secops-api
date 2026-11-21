variable "name" {
  type        = string
  description = "User pool, resource server and client name prefix."
  validation {
    condition     = length(trimspace(var.name)) > 0
    error_message = "Name cannot be empty."
  }
}

variable "domain" {
  type        = string
  description = "Globally unique Cognito hosted domain prefix."
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.domain))
    error_message = "Use a valid lowercase Cognito domain prefix."
  }
}

variable "resource_server_identifier" {
  type        = string
  description = "OAuth resource server identifier."
  default     = "soar-api"
  validation {
    condition     = length(trimspace(var.resource_server_identifier)) > 0
    error_message = "Resource server identifier cannot be empty."
  }
}

variable "scopes" {
  type        = map(string)
  description = "Scope names mapped to descriptions."
  default     = { "admin.readwrite.all" = "Full API access", "ioc.lookup.all" = "IOC lookup access" }
  validation {
    condition     = length(var.scopes) > 0 && alltrue([for k, v in var.scopes : length(k) > 0 && length(v) > 0])
    error_message = "Provide nonempty scope names and descriptions."
  }
}

variable "client_scopes" {
  type        = list(string)
  description = "Unqualified scope names allowed to the machine client. First scope is the authorization_scope output."
  default     = ["admin.readwrite.all"]
  validation {
    condition     = length(var.client_scopes) > 0 && alltrue([for s in var.client_scopes : contains(keys(var.scopes), s)])
    error_message = "Client scopes must name configured resource-server scopes."
  }
}

variable "tags" {
  type        = map(string)
  description = "Resource tags."
  default     = {}
}

