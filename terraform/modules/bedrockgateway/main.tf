data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_iam_policy_document" "assume_role_gateway" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock-agentcore.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "gateway_role" {
  name               = "bedrock-agentcore-gateway-role-soar-api"
  assume_role_policy = data.aws_iam_policy_document.assume_role_gateway.json
}

resource "aws_iam_role_policy_attachment" "default_policy_attachment_lambda_role_gateway" {
  role       = aws_iam_role.gateway_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "bedrock_agent_custom_execution_policy" {
  version = "2012-10-17"
  statement {
    sid    = "AllowBedrockAgentCoreAccessToken"
    effect = "Allow"
    actions = [
      "bedrock-agentcore:GetWorkloadAccessToken",
      "bedrock-agentcore:GetResourceOauth2Token",
    ]
    resources = [
      "arn:aws:bedrock-agentcore:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:workload-identity-directory/default",
      "arn:aws:bedrock-agentcore:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:workload-identity-directory/default/workload-identity/${var.gateway_name}-*"
    ]
  }
  statement {
    sid    = "AllowBedrockAgentCoreAuth2"
    effect = "Allow"
    actions = [
      "bedrock-agentcore:GetResourceOauth2Token",
    ]
    resources = [
      "arn:aws:bedrock-agentcore:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:token-vault/default*",
    ]
  }
  statement {
    sid    = "GetSecretValue"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
    ]
    resources = [
      "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:*",
    ]
  }
}

resource "aws_iam_policy" "bedrock_agent_custom_execution_policy" {
  name   = "agentcore-soarapi-agentcore-policy"
  policy = data.aws_iam_policy_document.bedrock_agent_custom_execution_policy.json
  tags   = var.tags
}

resource "aws_iam_policy_attachment" "policy_attachment_agentcore" {
  name       = "role-policy-attachment"
  roles      = [aws_iam_role.gateway_role.name]
  policy_arn = aws_iam_policy.bedrock_agent_custom_execution_policy.arn
}

resource "aws_bedrockagentcore_gateway" "gateway" {
  name            = var.gateway_name
  description     = var.gateway_description
  role_arn        = aws_iam_role.gateway_role.arn
  authorizer_type = var.authorization_type
  protocol_type   = "MCP"
  region          = data.aws_region.current.name
  authorizer_configuration {
    custom_jwt_authorizer {
      discovery_url    = "https://login.microsoftonline.com/${var.tenant_id}/v2.0/.well-known/openid-configuration"
      allowed_audience = var.audience_values
    }
  }
  tags = var.tags
}

resource "aws_bedrockagentcore_gateway_target" "soar_api" {
  name               = "SOARAPIModern"
  gateway_identifier = aws_bedrockagentcore_gateway.gateway.gateway_id
  description        = "This gateway enables our existing SOAR API to be accessible via MCP"
  region             = data.aws_region.current.name

  credential_provider_configuration {
    oauth { 
    # Provider needs to be created outside of terraform and has no data object
    # The client secret is stored in a secrets manager resource when creating from portal so need to add that.
      provider_arn = var.arn_oauth_outbound_provider
      grant_type   = "CLIENT_CREDENTIALS"
      scopes       = ["soar-api/admin.readwrite.all"]
    }
  }

  target_configuration {
    mcp {
      open_api_schema {
        inline_payload {
          payload = file("${path.module}/../../../openapi.yaml")
        }
      }
    }
  }
}
