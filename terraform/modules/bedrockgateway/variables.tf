variable "tags" {
  type        = map(string)
  description = "Tags to apply to the gateway"
}

variable "gateway_name" {
    type        = string
    description = "Name of the Bedrock Gateway"
}

variable "gateway_description" {
  type        = string
  description = "Description of the gateway"
}

variable "authorization_type" {
  type        = string
  description = "Authorization type for the gateway"
}

variable "tenant_id" {
  type        = string
  description = "Microsoft Tenant ID used for authentication to the gateway"
}

variable "audience_values" {
  type        = list(string)
  description = "List of audience values used for authentication to the gateway"
}

variable "arn_oauth_outbound_provider" {
  type        = string
  description = "ARN of the OAuth outbound provider used for authentication to the gateway"
}
