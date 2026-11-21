resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_iam_role" "this" {
  name_prefix = "${substr(var.name, 0, 26)}-"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "lambda.amazonaws.com" } }]
  })
  tags = var.tags
}

locals {
  execution_statements = concat([
    { Sid = "FunctionLogs", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = ["${aws_cloudwatch_log_group.this.arn}:*"] }
    ], var.tracing_enabled ? [
    # X-Ray does not support resource-level permissions for these write APIs.
    { Sid = "Tracing", Effect = "Allow", Action = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"], Resource = ["*"] }
    ] : [], !var.failure_notifications_enabled ? [] : [
    { Sid = "FailureDestination", Effect = "Allow", Action = ["sns:Publish"], Resource = [var.failure_topic_arn] }
  ], [for s in var.policy_statements : { Sid = s.sid, Effect = "Allow", Action = s.actions, Resource = s.resources }])
}

resource "aws_iam_role_policy" "this" {
  name   = "execution"
  role   = aws_iam_role.this.id
  policy = jsonencode({ Version = "2012-10-17", Statement = local.execution_statements })
}

resource "aws_lambda_function" "this" {
  function_name                  = var.name
  role                           = aws_iam_role.this.arn
  package_type                   = "Image"
  image_uri                      = var.image_uri
  architectures                  = [var.architecture]
  memory_size                    = var.memory_size
  timeout                        = var.timeout
  reserved_concurrent_executions = var.reserved_concurrent_executions
  dynamic "environment" {
    for_each = length(var.environment_variables) == 0 ? [] : [var.environment_variables]
    content { variables = environment.value }
  }
  logging_config {
    log_format = "JSON"
    log_group  = aws_cloudwatch_log_group.this.name
  }
  tracing_config { mode = var.tracing_enabled ? "Active" : "PassThrough" }
  tags       = var.tags
  depends_on = [aws_iam_role_policy.this]
}

resource "aws_lambda_function_event_invoke_config" "failure" {
  count                        = !var.failure_notifications_enabled ? 0 : 1
  function_name                = aws_lambda_function.this.function_name
  maximum_event_age_in_seconds = 21600
  maximum_retry_attempts       = 0
  destination_config {
    on_failure { destination = var.failure_topic_arn }
  }
}

resource "aws_cloudwatch_metric_alarm" "failure" {
  for_each            = !var.failure_notifications_enabled ? toset([]) : toset(["Errors", "Throttles"])
  alarm_name          = "${var.name}-${lower(each.value)}"
  namespace           = "AWS/Lambda"
  metric_name         = each.value
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { FunctionName = aws_lambda_function.this.function_name }
  alarm_actions       = [var.failure_topic_arn]
  tags                = var.tags
}
