resource "aws_api_gateway_rest_api" "gateway_object" {
  #checkov:skip=CKV_AWS_237: "Ensure Create before destroy for API Gateway" - Old API reference, is enabled below
  name        = var.api_gateway_name
  description = "API Gateway to act as Web Layer to SOAR API"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
  tags = var.tags
}

resource "aws_api_gateway_resource" "proxy_resource" {
  #When you define {proxy+}, it means that the API Gateway will match any path that comes after the base path, allowing for a flexible proxy setup.
  #If you want to access the root path, you need to ensure that the root resource is defined correctly as its own resource like this one.
  rest_api_id = aws_api_gateway_rest_api.gateway_object.id
  parent_id   = aws_api_gateway_rest_api.gateway_object.root_resource_id
  path_part   = "{proxy+}"
}

resource "aws_api_gateway_method" "proxy_method_lambda" {
  rest_api_id          = aws_api_gateway_rest_api.gateway_object.id
  resource_id          = aws_api_gateway_resource.proxy_resource.id
  http_method          = "ANY"
  api_key_required     = false
  authorization        = "COGNITO_USER_POOLS"
  authorizer_id        = aws_api_gateway_authorizer.cognito_authorizer.id
  authorization_scopes = ["soar-api/admin.readwrite.all"]
}

resource "aws_api_gateway_integration" "lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.gateway_object.id
  resource_id             = aws_api_gateway_resource.proxy_resource.id
  http_method             = aws_api_gateway_method.proxy_method_lambda.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = var.aws_lambda_function_arn
  timeout_milliseconds    = 29000
}

resource "aws_api_gateway_deployment" "single_deployment" {
  #if you update the resource policy after the API is created, you'll need to deploy the API to propagate the changes after you've attached the updated policy
  rest_api_id = aws_api_gateway_rest_api.gateway_object.id
  triggers = {
    redeployment = sha256(data.aws_iam_policy_document.api_gateway_resource_based_policy.json)
  }

  lifecycle {
    create_before_destroy = true
  }
  depends_on = [aws_api_gateway_rest_api_policy.resource_based_policy_attach]
}

resource "aws_api_gateway_stage" "core_stage" {
  rest_api_id   = aws_api_gateway_rest_api.gateway_object.id
  stage_name    = var.stage_name_api_gateway
  deployment_id = aws_api_gateway_deployment.single_deployment.id
  tags          = var.tags
}

data "aws_iam_policy_document" "api_gateway_resource_based_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["execute-api:Invoke"]
    resources = ["${aws_api_gateway_rest_api.gateway_object.execution_arn}/*/*/*"]

    # condition {
    #   test     = "IpAddress"
    #   variable = "aws:SourceIp"
    #   values   = var.trusted_ip_list_api_gw
    # }
  }
}

resource "aws_api_gateway_rest_api_policy" "resource_based_policy_attach" {
  rest_api_id = aws_api_gateway_rest_api.gateway_object.id
  policy      = data.aws_iam_policy_document.api_gateway_resource_based_policy.json
}

resource "aws_api_gateway_usage_plan" "default_usage_plan" {
  name        = var.api_gateway_usage_plan_name
  description = "Usage plan for API throttling and rate limiting"

  throttle_settings {
    burst_limit = var.api_burst_limit
    rate_limit  = var.api_rate_limit
  }
  api_stages {
    api_id = aws_api_gateway_rest_api.gateway_object.id
    stage  = aws_api_gateway_stage.core_stage.stage_name
  }
  tags = var.tags
}

########OpenID Connect Authorizer##########
resource "aws_api_gateway_authorizer" "cognito_authorizer" {
  name          = var.apigw_cognito_authorizer_name
  rest_api_id   = aws_api_gateway_rest_api.gateway_object.id
  type          = "COGNITO_USER_POOLS"
  provider_arns = [var.cognito_user_pool_arn]
}

resource "aws_lambda_permission" "api_gateway_trigger" {
  statement_id  = "AllowExecutionFromAPIGW"
  action        = "lambda:InvokeFunction"
  function_name = var.aws_lambda_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.gateway_object.execution_arn}/*/*/*" #All methods and stages
}
