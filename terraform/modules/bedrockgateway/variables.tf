variable "name" {
  type        = string
  description = "AgentCore gateway name."
  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9-]{0,99}$", var.name))
    error_message = "Use a gateway name beginning with a letter and containing letters, numbers or hyphens."
  }
}

variable "openapi_schema" {
  type        = string
  description = "Rendered OpenAPI YAML or JSON including the deployed API endpoint."
  validation {
    condition     = can(yamldecode(var.openapi_schema).openapi)
    error_message = "Supply a valid OpenAPI schema with an openapi version field."
  }
}

variable "discovery_url" {
  type        = string
  description = "Inbound JWT OpenID discovery URL."
  validation {
    condition     = can(regex("^https://.+/\\.well-known/openid-configuration$", var.discovery_url))
    error_message = "Supply an HTTPS OpenID discovery URL."
  }
}

variable "audiences" {
  type        = list(string)
  description = "Allowed inbound JWT audiences."
  validation {
    condition     = length(var.audiences) > 0 && alltrue([for a in var.audiences : length(trimspace(a)) > 0])
    error_message = "At least one audience is required."
  }
}

variable "oauth_provider_arn" {
  type        = string
  description = "Externally provisioned AgentCore outbound OAuth provider ARN."
  validation {
    condition     = can(regex("^arn:[^:]+:bedrock-agentcore:[^:]+:[0-9]{12}:token-vault/[^/]+/oauth2credentialprovider/.+$", var.oauth_provider_arn))
    error_message = "Supply a specific AgentCore OAuth provider ARN."
  }
}

variable "oauth_secret_arn" {
  type        = string
  description = "Exact Secrets Manager ARN backing the external OAuth provider."
  validation {
    condition     = can(regex("^arn:[^:]+:secretsmanager:[^:]+:[0-9]{12}:secret:[^*]+$", var.oauth_secret_arn))
    error_message = "Supply an exact Secrets Manager secret ARN without wildcards."
  }
}

variable "oauth_scopes" {
  type        = list(string)
  description = "Outbound OAuth scopes."
  validation {
    condition     = length(var.oauth_scopes) > 0
    error_message = "At least one OAuth scope is required."
  }
}

variable "tags" {
  type        = map(string)
  description = "Resource tags."
  default     = {}
}

