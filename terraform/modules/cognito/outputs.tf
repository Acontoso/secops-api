output "user_pool_id" {
  value = aws_cognito_user_pool.this.id
}

output "user_pool_arn" {
  value = aws_cognito_user_pool.this.arn
}

output "client_id" {
  value = aws_cognito_user_pool_client.this.id
}

output "issuer_url" {
  value = "https://cognito-idp.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}/${aws_cognito_user_pool.this.id}"
}

output "token_endpoint" {
  value = "https://${aws_cognito_user_pool_domain.this.domain}.auth.${data.aws_region.current.region}.amazoncognito.com/oauth2/token"
}

output "authorization_scope" {
  value = "${aws_cognito_resource_server.this.identifier}/${var.client_scopes[0]}"
}
