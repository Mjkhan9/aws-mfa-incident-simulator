# EventBridge rules for real-time CloudTrail event detection

# Note: These rules would detect REAL CloudTrail events in production.
# For the simulator, we trigger Lambda directly. These rules are included
# to demonstrate the detection architecture and for future integration.

# Rule 1: Detect ConsoleLogin failures (MFA auth failure pattern)
resource "aws_cloudwatch_event_rule" "console_login_failure" {
  name        = "${local.name_prefix}-console-login-failure"
  description = "Detect failed console login attempts consistent with MFA issues"

  event_pattern = jsonencode({
    source      = ["aws.signin"]
    detail-type = ["AWS Console Sign In via CloudTrail"]
    detail = {
      eventName = ["ConsoleLogin"]
      errorMessage = [{
        exists = true
      }]
    }
  })

  tags = {
    Name     = "${local.name_prefix}-console-login-failure"
    Scenario = "mfa_auth_failure"
  }
}

# Rule 2: Detect AccessDenied events (policy mismatch pattern)
resource "aws_cloudwatch_event_rule" "access_denied" {
  name        = "${local.name_prefix}-access-denied"
  description = "Detect AccessDenied errors that may indicate MFA policy mismatch"

  event_pattern = jsonencode({
    source = ["aws.iam", "aws.s3", "aws.ec2", "aws.sts"]
    detail = {
      errorCode = ["AccessDenied", "UnauthorizedAccess"]
    }
  })

  tags = {
    Name     = "${local.name_prefix}-access-denied"
    Scenario = "policy_mismatch"
  }
}

# Lambda permission for EventBridge rules (when using real CloudTrail events)
resource "aws_lambda_permission" "eventbridge_console_login" {
  statement_id  = "AllowEventBridgeConsoleLogin"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.simulator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.console_login_failure.arn
}

resource "aws_lambda_permission" "eventbridge_access_denied" {
  statement_id  = "AllowEventBridgeAccessDenied"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.simulator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.access_denied.arn
}

# Event targets for real CloudTrail integration
# These connect EventBridge rules to the Lambda for live detection

resource "aws_cloudwatch_event_target" "console_login_to_lambda" {
  rule      = aws_cloudwatch_event_rule.console_login_failure.name
  target_id = "process-console-login-failure"
  arn       = aws_lambda_function.simulator.arn
}

resource "aws_cloudwatch_event_target" "access_denied_to_lambda" {
  rule      = aws_cloudwatch_event_rule.access_denied.name
  target_id = "process-access-denied"
  arn       = aws_lambda_function.simulator.arn
}

output "eventbridge_rule_console_login" {
  description = "EventBridge rule for console login failures"
  value       = aws_cloudwatch_event_rule.console_login_failure.name
}

output "eventbridge_rule_access_denied" {
  description = "EventBridge rule for access denied events"
  value       = aws_cloudwatch_event_rule.access_denied.name
}

