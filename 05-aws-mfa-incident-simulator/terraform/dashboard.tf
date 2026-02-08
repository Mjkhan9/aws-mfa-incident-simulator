# CloudWatch Dashboard - Single Pane of Glass
# 4 widgets maximum for focused situational awareness

resource "aws_cloudwatch_dashboard" "incidents" {
  dashboard_name = "${local.name_prefix}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      # Widget 1: Incident Count by Type (last 24h)
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Incidents by Scenario (24h)"
          region = local.region
          metrics = [
            ["MFAIncidentSimulator", "IncidentCount", "Scenario", "mfa_auth_failure", "Environment", var.environment, { label = "MFA Auth Failure", color = "#ff7f0e" }],
            [".", ".", ".", "rate_limiting", ".", ".", { label = "Rate Limiting", color = "#d62728" }],
            [".", ".", ".", "policy_mismatch", ".", ".", { label = "Policy Mismatch", color = "#9467bd" }]
          ]
          stat   = "Sum"
          period = 3600
          view   = "timeSeries"
          stacked = true
        }
      },
      
      # Widget 2: Failed ConsoleLogin over time
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Incident Volume Over Time"
          region = local.region
          metrics = [
            ["MFAIncidentSimulator", "IncidentCount", "Environment", var.environment, { label = "Total Incidents", color = "#1f77b4" }]
          ]
          stat   = "Sum"
          period = 300
          view   = "timeSeries"
        }
      },
      
      # Widget 3: Resolution Time (Simulated MTTR)
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Simulated Resolution Time"
          region = local.region
          metrics = [
            ["MFAIncidentSimulator", "ResolutionTimeSeconds", "Environment", var.environment, { label = "Avg Resolution (s)", color = "#2ca02c" }]
          ]
          stat   = "Average"
          period = 300
          view   = "timeSeries"
          yAxis = {
            left = {
              min   = 0
              label = "Seconds"
            }
          }
        }
      },
      
      # Widget 4: Active Incidents (gauge-style single value)
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Recent Incident Activity"
          region = local.region
          metrics = [
            ["MFAIncidentSimulator", "IncidentCount", "Severity", "HIGH", "Environment", var.environment, { label = "HIGH", color = "#d62728" }],
            [".", ".", ".", "MEDIUM", ".", ".", { label = "MEDIUM", color = "#ff7f0e" }],
            ["MFAIncidentSimulator", "IncidentResolved", "Environment", var.environment, { label = "Resolved", color = "#2ca02c" }]
          ]
          stat   = "Sum"
          period = 3600
          view   = "singleValue"
          setPeriodToTimeRange = true
        }
      }
    ]
  })
}

output "dashboard_url" {
  description = "CloudWatch Dashboard URL"
  value       = "https://${local.region}.console.aws.amazon.com/cloudwatch/home?region=${local.region}#dashboards:name=${aws_cloudwatch_dashboard.incidents.dashboard_name}"
}

