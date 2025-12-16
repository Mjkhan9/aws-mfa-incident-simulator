# SNS topic for incident alerts

resource "aws_sns_topic" "incidents" {
  name = "${local.name_prefix}-alerts"

  tags = {
    Name = "${local.name_prefix}-alerts"
  }
}

# Email subscription (optional - only if email provided)
resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.incidents.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# SNS topic policy allowing Lambda to publish
resource "aws_sns_topic_policy" "incidents" {
  arn = aws_sns_topic.incidents.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowLambdaPublish"
        Effect    = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.incidents.arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:aws:lambda:${local.region}:${local.account_id}:function:${local.name_prefix}-*"
          }
        }
      }
    ]
  })
}

output "sns_topic_arn" {
  description = "SNS topic ARN for incident alerts"
  value       = aws_sns_topic.incidents.arn
}

