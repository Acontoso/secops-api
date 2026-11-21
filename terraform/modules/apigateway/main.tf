data "aws_caller_identity" "current" {}

resource "aws_api_gateway_rest_api" "this" {
  name = var.name
  endpoint_configuration { types = ["REGIONAL"] }
  tags = var.tags
}

resource "aws_api_gateway_resource" "proxy" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_rest_api.this.root_resource_id
  path_part   = "{proxy+}"
}

locals {
  resource_ids = { root = aws_api_gateway_rest_api.this.root_resource_id, proxy = aws_api_gateway_resource.proxy.id }
}

resource "aws_api_gateway_authorizer" "this" {
  name            = "${var.name}-cognito"
  rest_api_id     = aws_api_gateway_rest_api.this.id
  type            = "COGNITO_USER_POOLS"
  provider_arns   = [var.cognito_user_pool_arn]
  identity_source = "method.request.header.Authorization"
}

resource "aws_api_gateway_method" "this" {
  for_each             = local.resource_ids
  rest_api_id          = aws_api_gateway_rest_api.this.id
  resource_id          = each.value
  http_method          = "ANY"
  api_key_required     = false
  authorization        = "COGNITO_USER_POOLS"
  authorizer_id        = aws_api_gateway_authorizer.this.id
  authorization_scopes = var.authorization_scopes
}

resource "aws_api_gateway_integration" "this" {
  for_each                = local.resource_ids
  rest_api_id             = aws_api_gateway_rest_api.this.id
  resource_id             = each.value
  http_method             = aws_api_gateway_method.this[each.key].http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = var.lambda_invoke_arn
  timeout_milliseconds    = 29000
}

locals {
  resource_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = "*", Action = "execute-api:Invoke", Resource = "${aws_api_gateway_rest_api.this.execution_arn}/*/*/*" }]
  })
}

# Public reachability is intentional; every route requires Cognito access scopes.
resource "aws_api_gateway_rest_api_policy" "this" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  policy      = local.resource_policy
}

resource "aws_api_gateway_deployment" "this" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  triggers = {
    redeployment = sha256(jsonencode({
      resources    = local.resource_ids
      methods      = aws_api_gateway_method.this
      integrations = aws_api_gateway_integration.this
      authorizer   = aws_api_gateway_authorizer.this
      policy       = local.resource_policy
      endpoint     = aws_api_gateway_rest_api.this.endpoint_configuration
    }))
  }
  depends_on = [aws_api_gateway_rest_api_policy.this]
  lifecycle { create_before_destroy = true }
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/apigateway/${var.name}/${var.stage_name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_iam_role" "logging" {
  count       = var.cloudwatch_role_arn == null ? 1 : 0
  name_prefix = "apigateway-logs-"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "apigateway.amazonaws.com" } }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "logging" {
  count = var.cloudwatch_role_arn == null ? 1 : 0
  name  = "access-logs"
  role  = aws_iam_role.logging[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["logs:DescribeLogGroups"], Resource = "*" },
      { Effect = "Allow", Action = ["logs:DescribeLogStreams", "logs:CreateLogStream", "logs:PutLogEvents", "logs:GetLogEvents", "logs:FilterLogEvents"], Resource = "${aws_cloudwatch_log_group.this.arn}:*" }
    ]
  })
}

# API Gateway has one account logging setting per region. The default branch
# owns it; other APIs must pass cloudwatch_role_arn and manage that setting once.
resource "aws_api_gateway_account" "this" {
  count               = var.cloudwatch_role_arn == null ? 1 : 0
  cloudwatch_role_arn = aws_iam_role.logging[0].arn
  depends_on          = [aws_iam_role_policy.logging]
}

resource "aws_api_gateway_stage" "this" {
  rest_api_id          = aws_api_gateway_rest_api.this.id
  stage_name           = var.stage_name
  deployment_id        = aws_api_gateway_deployment.this.id
  xray_tracing_enabled = var.tracing_enabled
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.this.arn
    # Never log headers, tokens, bodies or query strings.
    format = jsonencode({
      requestId    = "$context.requestId", extendedRequestId = "$context.extendedRequestId",
      requestTime  = "$context.requestTime", httpMethod = "$context.httpMethod",
      resourcePath = "$context.resourcePath", status = "$context.status",
      protocol     = "$context.protocol", responseLength = "$context.responseLength"
    })
  }
  tags       = var.tags
  depends_on = [aws_api_gateway_account.this]
}

resource "aws_api_gateway_method_settings" "this" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  stage_name  = aws_api_gateway_stage.this.stage_name
  method_path = "*/*"
  settings {
    metrics_enabled        = true
    data_trace_enabled     = false
    logging_level          = "OFF"
    throttling_rate_limit  = var.rate_limit
    throttling_burst_limit = var.burst_limit
  }
}

resource "aws_lambda_permission" "this" {
  statement_id   = "AllowAPIGateway-${var.stage_name}"
  action         = "lambda:InvokeFunction"
  function_name  = var.lambda_function_name
  principal      = "apigateway.amazonaws.com"
  source_account = data.aws_caller_identity.current.account_id
  source_arn     = "${aws_api_gateway_rest_api.this.execution_arn}/${var.stage_name}/*/*"
}
