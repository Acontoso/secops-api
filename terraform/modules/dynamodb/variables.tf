variable "tags" {
  type        = map(string)
  description = "Tags to apply to the gateway"
}

variable "dynamodb_table_name_ioc" {
  type        = string
  description = "Name of DynamoDB table for IOCs"
}

variable "dynamodb_primary_key_ioc" {
  type        = string
  description = "DynamoDB partition key for IOCs"
}

variable "dynamodb_sort_key_ioc" {
  type        = string
  description = "DynamoDB sort key for IOCs"
}

variable "dynamodb_table_name_actions" {
  type        = string
  description = "Name of DynamoDB table for SOAR actions"
}

variable "dynamodb_primary_key_actions" {
  type        = string
  description = "DynamoDB partition key for SOAR actions"
}

variable "dynamodb_sort_key_actions" {
  type        = string
  description = "DynamoDB sort key for SOAR actions"
}
