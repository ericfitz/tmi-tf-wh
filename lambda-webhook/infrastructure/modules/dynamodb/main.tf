#
# DynamoDB Module - Idempotency Table
#
# This module creates a DynamoDB table for tracking webhook delivery IDs
# to prevent duplicate processing.
#

resource "aws_dynamodb_table" "idempotency" {
  name         = "${var.resource_prefix}-webhook-deliveries"
  billing_mode = "PAY_PER_REQUEST" # On-demand billing (no capacity planning)
  hash_key     = "delivery_id"

  attribute {
    name = "delivery_id"
    type = "S" # String
  }

  ttl {
    enabled        = true
    attribute_name = "ttl"
  }

  point_in_time_recovery {
    enabled = var.environment == "prod" ? true : false
  }

  server_side_encryption {
    enabled = true
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.resource_prefix}-webhook-deliveries"
    }
  )
}
