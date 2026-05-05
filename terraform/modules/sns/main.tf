module "sns" {
  #checkov:skip=CKV_TF_1: "Ensure Terraform module sources use a commit hash"
  #checkov:skip=CKV2_AWS_73: "Ensure AWS SQS uses CMK not AWS default keys for encryption"
  source  = "cloudposse/sns-topic/aws"
  version = "0.21.0" #github release, linked to commit hash

  name                                   = var.sns_topic_name
  allowed_aws_services_for_sns_published = ["lambda.amazonaws.com"]
  encryption_enabled                     = false

  subscribers = {
    internal = {
      protocol               = "email"
      endpoint               = "email@email.com"
      endpoint_auto_confirms = false
      raw_message_delivery   = false
    }
  }

  sqs_dlq_enabled = false
  tags            = var.tags
}
