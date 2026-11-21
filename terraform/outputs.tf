output "api_url" {
  description = "Authenticated regional REST API stage URL."
  value       = module.api.invoke_url
}

output "function_name" {
  description = "Image-based Lambda function name."
  value       = module.function.function_name
}

output "image_uri" {
  description = "Immutable image selected by this deployment."
  value       = var.image_uri
}

output "user_pool_id" {
  description = "Cognito user pool used by API Gateway and application authentication."
  value       = module.authorization.user_pool_id
}

output "client_id" {
  description = "Machine-to-machine client ID (not its secret)."
  value       = module.authorization.client_id
}

output "authorization_scope" {
  description = "Fully qualified OAuth scope required by the API."
  value       = module.authorization.authorization_scope
}

output "token_endpoint" {
  description = "OAuth client-credentials token endpoint."
  value       = module.authorization.token_endpoint
}

output "ssm_parameter_prefix" {
  description = "Populate externally with SecureStrings containing base64 KMS ciphertext."
  value       = local.ssm_prefix
}

output "notification_topic_arn" {
  description = "Operational notification topic; subscriptions must be confirmed separately."
  value       = module.notifications.topic_arn
}

output "agentcore_gateway_url" {
  description = "Optional AgentCore endpoint; null before external OAuth setup."
  value       = try(module.agentcore[0].gateway_url, null)
}
