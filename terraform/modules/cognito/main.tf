data "aws_region" "current" {}
data "aws_partition" "current" {}

resource "aws_cognito_user_pool" "this" {
  name           = var.name
  user_pool_tier = "LITE"
  admin_create_user_config { allow_admin_create_user_only = true }
  tags = var.tags
}

resource "aws_cognito_user_pool_domain" "this" {
  domain       = var.domain
  user_pool_id = aws_cognito_user_pool.this.id
}

resource "aws_cognito_resource_server" "this" {
  identifier   = var.resource_server_identifier
  name         = var.name
  user_pool_id = aws_cognito_user_pool.this.id
  dynamic "scope" {
    for_each = var.scopes
    content {
      scope_name        = scope.key
      scope_description = scope.value
    }
  }
}

# Cognito necessarily persists the generated client secret in Terraform state.
# Retrieve/distribute it out of band; do not expose it as a module output.
resource "aws_cognito_user_pool_client" "this" {
  name                                 = "${var.name}-machine"
  user_pool_id                         = aws_cognito_user_pool.this.id
  generate_secret                      = true
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["client_credentials"]
  allowed_oauth_scopes                 = [for s in var.client_scopes : "${aws_cognito_resource_server.this.identifier}/${s}"]
  access_token_validity                = 1
  enable_token_revocation              = true
  prevent_user_existence_errors        = "ENABLED"
  explicit_auth_flows                  = ["ALLOW_REFRESH_TOKEN_AUTH"]
  supported_identity_providers         = ["COGNITO"]
}
