variable "tags" {
  type        = map(string)
  description = "Tags to apply to the gateway"
}

variable "sns_topic_name" {
  type        = string
  description = "SNS topic name"
}
