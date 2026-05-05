variable "tags" {
  type        = map(string)
  description = "Tags to apply to the gateway"
}

variable "cognito_oidc_userpool" {
  type        = string
  description = "Name of the Cognito OIDC user pool"
}

variable "cognito_domain_name" {
  type        = string
  description = "Cognito domain name for the user pool"
}

variable "cognito_oidc_client_app" {
  type        = string
  description = "Name of the Cognito OIDC client application"
}

variable "identity_pool_name" {
  type        = string
  description = "Name of the Cognito OIDC identity pool"
  default = "azure-ad-oidc-sentinel"
}
