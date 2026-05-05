output "sns_arn" {
  description = "ARN of SNS topic created"
  value = module.sns.sns_topic_arn
}