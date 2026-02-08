# DynamoDB table for incident storage

resource "aws_dynamodb_table" "incidents" {
  name         = "${local.name_prefix}-incidents"
  billing_mode = "PAY_PER_REQUEST"  # On-demand for cost efficiency
  hash_key     = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  # Global Secondary Index for querying by scenario and status
  attribute {
    name = "scenario"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "N"
  }

  global_secondary_index {
    name            = "scenario-created-index"
    hash_key        = "scenario"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # Enable TTL for automatic cleanup
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  # Point-in-time recovery for audit compliance
  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name = "${local.name_prefix}-incidents"
  }
}

# Output the table name for Lambda environment variables
output "incidents_table_name" {
  description = "DynamoDB table name for incidents"
  value       = aws_dynamodb_table.incidents.name
}

output "incidents_table_arn" {
  description = "DynamoDB table ARN"
  value       = aws_dynamodb_table.incidents.arn
}

