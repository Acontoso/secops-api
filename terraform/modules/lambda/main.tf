data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_kms_key" "ssm_kms_alias" {
  key_id = "alias/cmk-ssm"
}

data "aws_s3_object" "lambda_zip" {
  #Reference the object in the S3 bucket after the upload has successfully completed
  bucket     = data.aws_s3_bucket.artefact_bucket.id
  key        = "code.zip"
  depends_on = [null_resource.upload_lambda_zip]
}

data "aws_s3_bucket" "artefact_bucket" {
  bucket = var.s3_bucket_name
}

resource "null_resource" "upload_lambda_zip" {
  triggers = {
    always_run = timestamp()
  }
  depends_on = [data.archive_file.code]
  provisioner "local-exec" {
    command = "aws s3 cp ${path.root}/terraform/code.zip s3://${data.aws_s3_bucket.artefact_bucket.id}/code.zip"
  }
}

resource "aws_lambda_function" "lambda" {
  function_name    = var.lambda_function_name
  role             = aws_iam_role.lambda_role.arn
  s3_bucket        = data.aws_s3_bucket.artefact_bucket.id
  s3_key           = "code.zip"
  handler          = var.handler
  runtime          = var.runtime
  memory_size      = var.memory_size
  tags             = var.tags
  timeout          = var.timeout
  description      = var.description
  source_code_hash = data.aws_s3_object.lambda_zip.etag
  logging_config {
    log_format = "JSON"
  }
  environment {
    variables = {
      "IOC_TABLE_NAME"              = var.dynamodb_table_name_ioc
      "IOC_TABLE_HASH_KEY"          = var.dynamodb_primary_key_ioc
      "IOC_TABLE_SORT_KEY"          = var.dynamodb_sort_key_ioc
      "SOAR_ACTIONS_TABLE_NAME"     = var.dynamodb_table_name_actions
      "SOAR_ACTIONS_TABLE_HASH_KEY" = var.dynamodb_primary_key_actions
      "SOAR_ACTIONS_SORT_KEY"       = var.dynamodb_sort_key_actions
      "TENANT_ID"                   = var.ms_tenant_id
      "IDENTITY_POOL_ID"            = var.identity_pool_id
      "IDENTITY_POOL_LOGIN"         = var.identity_pool_login
    }
  }
  depends_on = [null_resource.upload_lambda_zip]
}

resource "null_resource" "go_compile" {
  triggers = {
    always_run = timestamp()
  }
  #Compile Go application for Lambda
  # This builds the Go binary and outputs it as 'bootstrap' in the code directory
  provisioner "local-exec" {
    command = "cd ${path.module}/../../../code && GOOS=linux GOARCH=amd64 go build -ldflags=\"-w -s\" -o bootstrap ."
  }
}

# The code directory is zipped and stored in the terraform directory to be uploaded to S3.
# This includes the compiled Go binary (bootstrap) which Lambda will execute

data "archive_file" "code" {
  type        = "zip"
  source_dir  = "${path.module}/../../../code"               # Use code dir for Go application
  output_path = "${path.root}/terraform/code.zip"      # Use absolute path for CI/CD reliability
  excludes    = ["*.go", "go.mod", "go.sum", "tst.py"] # Exclude source files, keep only bootstrap binary
  depends_on  = [null_resource.go_compile]
}

data "aws_iam_policy_document" "lambda_custom_execution_policy" {
  version = "2012-10-17"
  statement {
    sid    = "AllowSSM"
    effect = "Allow"
    actions = [
      "ssm:GetParameter*"
    ]
    resources = [
      "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/soar-api/*"
    ]
  }
  statement {
    sid    = "AllowSnsPublish"
    effect = "Allow"
    actions = [
      "sns:Publish",
    ]
    resources = [
      var.sns_topic_arn
    ]
  }
  statement {
    sid    = "AllowKMS"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [
      data.aws_kms_key.ssm_kms_alias.arn
    ]
  }
  statement {
    sid    = "AllowDynamoDB"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:Query",
      "dynamodb:GetItem",
      "dynamodb:BatchGetItem",
      "dynamodb:BatchWriteItem"
    ]
    resources = [
      var.dynamodb_table_arn_ioc,
      var.dynamodb_table_arn_actions
    ]
  }
  statement {
    sid    = "CognitoIdentityPoolOIDC"
    effect = "Allow"
    actions = [
      "cognito-identity:GetOpenIdTokenForDeveloperIdentity",
      "cognito-identity:LookupDeveloperIdentity",
      "cognito-identity:MergeDeveloperIdentities",
      "cognito-identity:UnlinkDeveloperIdentity"
    ]
    resources = [
      var.cognito_identity_pool_arn
    ]
  }
}

resource "aws_iam_policy" "lambda_iam_policy" {
  name   = "${var.lambda_function_name}-lambda-policy"
  policy = data.aws_iam_policy_document.lambda_custom_execution_policy.json
  tags   = var.tags
}

resource "aws_iam_role" "lambda_role" {
  name               = "${var.lambda_function_name}-lambda-execution-role"
  assume_role_policy = data.aws_iam_policy_document.trust_policy_document_lambda.json
  tags               = var.tags
}

data "aws_iam_policy_document" "trust_policy_document_lambda" {
  statement {
    sid    = "LambdaTrustPolicy"
    effect = "Allow"

    actions = [
      "sts:AssumeRole",
    ]

    principals {
      identifiers = [
        "lambda.amazonaws.com",
      ]

      type = "Service"
    }
  }
}

resource "aws_iam_policy_attachment" "policy_attachment_lambda_role" {
  name       = "role-policy-attachment"
  roles      = [aws_iam_role.lambda_role.name]
  policy_arn = aws_iam_policy.lambda_iam_policy.arn
}

resource "aws_iam_role_policy_attachment" "default_policy_attachment_lambda_role" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function_event_invoke_config" "lambda_retry_failure" {
  function_name                = aws_lambda_function.lambda.function_name
  maximum_event_age_in_seconds = 21600
  maximum_retry_attempts       = 0
  destination_config {
    on_failure {
      destination = var.sns_topic_arn
    }
  }
}
