data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  agentcore_arn = "arn:${data.aws_partition.current.partition}:bedrock-agentcore:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}"
}

resource "aws_iam_role" "this" {
  name_prefix = "${substr(var.name, 0, 26)}-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "bedrock-agentcore.amazonaws.com" }
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike      = { "aws:SourceArn" = "${local.agentcore_arn}:gateway/*" }
      }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "this" {
  name = "outbound-oauth"
  role = aws_iam_role.this.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WorkloadIdentity"
        Effect   = "Allow"
        Action   = ["bedrock-agentcore:GetWorkloadAccessToken"]
        Resource = ["${local.agentcore_arn}:workload-identity-directory/default", aws_bedrockagentcore_gateway.this.workload_identity_details[0].workload_identity_arn]
      },
      {
        Sid      = "OutboundOAuth"
        Effect   = "Allow"
        Action   = ["bedrock-agentcore:GetResourceOauth2Token"]
        Resource = [var.oauth_provider_arn]
      },
      {
        Sid      = "OAuthSecret"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [var.oauth_secret_arn]
      }
    ]
  })
}

resource "aws_bedrockagentcore_gateway" "this" {
  name            = var.name
  role_arn        = aws_iam_role.this.arn
  authorizer_type = "CUSTOM_JWT"
  protocol_type   = "MCP"
  authorizer_configuration {
    custom_jwt_authorizer {
      discovery_url    = var.discovery_url
      allowed_audience = var.audiences
    }
  }
  tags = var.tags
}

resource "aws_bedrockagentcore_gateway_target" "this" {
  name               = "${var.name}-api"
  gateway_identifier = aws_bedrockagentcore_gateway.this.gateway_id
  depends_on         = [aws_iam_role_policy.this]
  credential_provider_configuration {
    oauth {
      provider_arn = var.oauth_provider_arn
      grant_type   = "CLIENT_CREDENTIALS"
      scopes       = var.oauth_scopes
    }
  }
  target_configuration {
    mcp {
      open_api_schema {
        inline_payload { payload = var.openapi_schema }
      }
    }
  }
}
