resource "aws_ssm_parameter" "this" {
  for_each    = var.parameters
  name        = each.value.name
  type        = "SecureString"
  description = each.value.description
  key_id      = var.kms_key_id
  value       = each.value.value
  tags        = var.tags
}
