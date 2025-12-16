# CloudWatch alarms and metric filters

# Alarm: High incident volume (>10 incidents in 5 minutes)
resource "aws_cloudwatch_metric_alarm" "high_incident_volume" {
  alarm_name          = "${local.name_prefix}-high-incident-volume"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "IncidentCount"
  namespace           = "MFAIncidentSimulator"
  period              = 300  # 5 minutes
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "High volume of MFA incidents detected"
  treat_missing_data  = "notBreaching"

  dimensions = {
    Environment = var.environment
  }

  alarm_actions = [aws_sns_topic.incidents.arn]
  ok_actions    = [aws_sns_topic.incidents.arn]

  tags = {
    Name = "${local.name_prefix}-high-incident-volume"
  }
}

# Alarm: Critical severity incidents
resource "aws_cloudwatch_metric_alarm" "critical_incidents" {
  alarm_name          = "${local.name_prefix}-critical-incidents"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "IncidentCount"
  namespace           = "MFAIncidentSimulator"
  period              = 60  # 1 minute
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Critical severity MFA incident detected"
  treat_missing_data  = "notBreaching"

  dimensions = {
    Environment = var.environment
    Severity    = "CRITICAL"
  }

  alarm_actions = [aws_sns_topic.incidents.arn]

  tags = {
    Name = "${local.name_prefix}-critical-incidents"
  }
}

# Alarm: Slow resolution time (>10 minutes average)
resource "aws_cloudwatch_metric_alarm" "slow_resolution" {
  alarm_name          = "${local.name_prefix}-slow-resolution"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "ResolutionTimeSeconds"
  namespace           = "MFAIncidentSimulator"
  period              = 300
  statistic           = "Average"
  threshold           = 600  # 10 minutes
  alarm_description   = "Average resolution time exceeds 10 minutes"
  treat_missing_data  = "notBreaching"

  dimensions = {
    Environment = var.environment
  }

  alarm_actions = [aws_sns_topic.incidents.arn]

  tags = {
    Name = "${local.name_prefix}-slow-resolution"
  }
}

# Alarm: Lambda function errors (uses built-in Lambda metrics)
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${local.name_prefix}-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "High number of Lambda function errors"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = "${local.name_prefix}-simulator"
  }

  alarm_actions = [aws_sns_topic.incidents.arn]

  tags = {
    Name = "${local.name_prefix}-lambda-errors"
  }
}

