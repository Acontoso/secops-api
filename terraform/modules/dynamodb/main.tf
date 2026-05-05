resource "aws_dynamodb_table" "ioc_table" {
  name                        = var.dynamodb_table_name_ioc
  billing_mode                = "PAY_PER_REQUEST"
  deletion_protection_enabled = true
  hash_key                    = var.dynamodb_primary_key_ioc
  range_key                   = var.dynamodb_sort_key_ioc

  attribute {
    name = "IOC"
    type = "S"
  }

  attribute {
    name = "IOCType"
    type = "S"
  }

  attribute {
    name = "EnrichmentSource"
    type = "S"
  }

  attribute {
    name = "Date"
    type = "S"
  }

  attribute {
    name = "IncidentID"
    type = "S"
  }

  attribute {
    name = "MaliciousConfidence"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
  global_secondary_index {
    hash_key        = "IOCType"
    name            = "IOCTypeDate"
    projection_type = "ALL"
    range_key       = "Date"
  }
  global_secondary_index {
    hash_key        = "IOCType"
    name            = "IOCTypeConfidence"
    projection_type = "ALL"
    range_key       = "MaliciousConfidence"
  }
  global_secondary_index {
    hash_key        = "IOCType"
    name            = "IOCTypeIncident"
    projection_type = "ALL"
    range_key       = "IncidentID"
  }
  tags = var.tags
}

resource "aws_dynamodb_table" "actions_table" {
  name                        = var.dynamodb_table_name_actions
  billing_mode                = "PAY_PER_REQUEST"
  deletion_protection_enabled = true
  hash_key                    = var.dynamodb_primary_key_actions
  range_key                   = var.dynamodb_sort_key_actions

  attribute {
    name = "IOC"
    type = "S"
  }

  attribute {
    name = "Integration"
    type = "S"
  }

  attribute {
    name = "Date"
    type = "S"
  }

  attribute {
    name = "IncidentID"
    type = "S"
  }

  global_secondary_index {
    hash_key        = "IOC"
    name            = "IOCIncident"
    projection_type = "ALL"
    range_key       = "IncidentID"
  }

  global_secondary_index {
    hash_key        = "IOC"
    name            = "IOCDate"
    projection_type = "ALL"
    range_key       = "Date"
  }

  point_in_time_recovery {
    enabled = true
  }
  tags = var.tags
}
