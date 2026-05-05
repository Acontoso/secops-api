output "ioc_table_arn" {
  description = "ARN of the DynamoDB table for IOCs"
  value       = aws_dynamodb_table.ioc_table.arn
}

output "actions_table_arn" {
  description = "ARN of the DynamoDB table for SOAR actions"
  value       = aws_dynamodb_table.actions_table.arn
}
