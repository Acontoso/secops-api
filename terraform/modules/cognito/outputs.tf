output "cognito_identity_pool_arn" {
    description = "ARN of the Cognito Identity Pool"
    value       = data.aws_cognito_identity_pool.identity_pool_oidc.arn
}

output "aws_cognito_user_pool_arn" {
    description = "ARN of the Cognito User Pool"
    value       = aws_cognito_user_pool.oidc_userpool.arn
}
