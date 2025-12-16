# Variables for MFA Incident Simulator

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "mfa-incident-simulator"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "alert_email" {
  description = "Email address for incident alerts"
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 14
}

variable "incident_retention_days" {
  description = "DynamoDB incident TTL in days"
  type        = number
  default     = 7
}

variable "responder_schedule" {
  description = "Schedule expression for responder Lambda (rate or cron)"
  type        = string
  default     = "rate(5 minutes)"
}

