data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_ecr_repository" "this" {
  name                 = var.name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration { encryption_type = "AES256" }
  tags = var.tags
  lifecycle {
    precondition {
      condition     = var.allowed_account_id == data.aws_caller_identity.current.account_id
      error_message = "Lambda image retrieval must be limited to the repository account."
    }
  }
}

# Deliberately no lifecycle expiration: a deployed/promoted digest must survive
# even when it becomes untagged. Image cleanup is an explicit operator action.
resource "aws_ecr_repository_policy" "lambda" {
  repository = aws_ecr_repository.this.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "LambdaImageRetrieval"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
      Condition = { ArnLike = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.region}:${var.allowed_account_id}:function:*" } }
    }]
  })
}
