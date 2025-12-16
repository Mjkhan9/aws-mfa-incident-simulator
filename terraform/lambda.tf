# Lambda functions for incident simulation and response

# Use existing lab Lambda execution role
variable "lambda_role_arn" {
  description = "ARN of existing Lambda execution role"
  type        = string
  default     = "arn:aws:iam::637423174317:role/LabRole"
}

# Package Lambda code
data "archive_file" "simulator" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/simulator"
  output_path = "${path.module}/files/simulator.zip"
}

data "archive_file" "responder" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/responder"
  output_path = "${path.module}/files/responder.zip"
}

# Simulator Lambda
resource "aws_lambda_function" "simulator" {
  filename         = data.archive_file.simulator.output_path
  function_name    = "${local.name_prefix}-simulator"
  role             = var.lambda_role_arn
  handler          = "handler.lambda_handler"
  source_code_hash = data.archive_file.simulator.output_base64sha256
  runtime          = "python3.11"
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      INCIDENTS_TABLE = aws_dynamodb_table.incidents.name
      SNS_TOPIC_ARN   = aws_sns_topic.incidents.arn
      ENVIRONMENT     = var.environment
    }
  }

  tags = {
    Name = "${local.name_prefix}-simulator"
  }
}

# Responder Lambda
resource "aws_lambda_function" "responder" {
  filename         = data.archive_file.responder.output_path
  function_name    = "${local.name_prefix}-responder"
  role             = var.lambda_role_arn
  handler          = "handler.lambda_handler"
  source_code_hash = data.archive_file.responder.output_base64sha256
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 128

  environment {
    variables = {
      INCIDENTS_TABLE = aws_dynamodb_table.incidents.name
      SNS_TOPIC_ARN   = aws_sns_topic.incidents.arn
      ENVIRONMENT     = var.environment
    }
  }

  tags = {
    Name = "${local.name_prefix}-responder"
  }
}

# CloudWatch Log Groups with retention
resource "aws_cloudwatch_log_group" "simulator" {
  name              = "/aws/lambda/${aws_lambda_function.simulator.function_name}"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "responder" {
  name              = "/aws/lambda/${aws_lambda_function.responder.function_name}"
  retention_in_days = var.log_retention_days
}

# EventBridge rule to trigger responder on schedule
resource "aws_cloudwatch_event_rule" "responder_schedule" {
  name                = "${local.name_prefix}-responder-schedule"
  description         = "Trigger responder Lambda to check for incidents eligible for remediation"
  schedule_expression = var.responder_schedule
}

resource "aws_cloudwatch_event_target" "responder" {
  rule      = aws_cloudwatch_event_rule.responder_schedule.name
  target_id = "responder-lambda"
  arn       = aws_lambda_function.responder.arn
}

resource "aws_lambda_permission" "responder_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.responder_schedule.arn
}

# Outputs
output "simulator_function_name" {
  description = "Simulator Lambda function name"
  value       = aws_lambda_function.simulator.function_name
}

output "simulator_function_arn" {
  description = "Simulator Lambda function ARN"
  value       = aws_lambda_function.simulator.arn
}

output "responder_function_name" {
  description = "Responder Lambda function name"
  value       = aws_lambda_function.responder.function_name
}

