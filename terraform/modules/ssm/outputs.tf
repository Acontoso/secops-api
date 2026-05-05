output "parameter_arns" {
  description = "ARNs of all created SSM parameters"
  value       = { for k, v in aws_ssm_parameter.this : k => v.arn }
}

output "parameter_names" {
  description = "Names of all created SSM parameters"
  value       = { for k, v in aws_ssm_parameter.this : k => v.name }
}
