data "aws_cognito_identity_pool" "identity_pool_oidc" {
  identity_pool_name = var.identity_pool_name
}

resource "aws_cognito_user_pool" "oidc_userpool" {
  name           = var.cognito_oidc_userpool
  user_pool_tier = "LITE"
  tags           = var.tags
}

resource "aws_cognito_user_pool_domain" "cognito_domain" {
  domain       = var.cognito_domain_name
  user_pool_id = aws_cognito_user_pool.oidc_userpool.id
}

resource "aws_cognito_resource_server" "soar_api_resource_server" {
  identifier = "soar-api"
  name       = "SOAR API"

  scope {
    scope_name        = "admin.readwrite.all"
    scope_description = "Scope that has full access to the API"
  }

  scope {
    scope_name        = "ioc.lookup.all"
    scope_description = "Scope that has full access to the API"
  }

  user_pool_id = aws_cognito_user_pool.oidc_userpool.id
}

resource "aws_cognito_user_pool_client" "az_logic_apps_client" {
  name                                 = var.cognito_oidc_client_app
  generate_secret                      = true
  access_token_validity                = 1
  refresh_token_validity               = 1
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["client_credentials"]
  allowed_oauth_scopes                 = ["soar-api/admin.readwrite.all"]
  enable_token_revocation              = true
  explicit_auth_flows                  = ["ALLOW_REFRESH_TOKEN_AUTH"]
  user_pool_id                         = aws_cognito_user_pool.oidc_userpool.id
}
