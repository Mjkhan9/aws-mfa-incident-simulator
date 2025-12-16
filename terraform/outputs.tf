# Consolidated outputs for MFA Incident Simulator

output "project_info" {
  description = "Project deployment information"
  value = {
    project_name = var.project_name
    environment  = var.environment
    region       = local.region
    account_id   = local.account_id
  }
}

output "invoke_commands" {
  description = "AWS CLI commands to invoke the simulator"
  value = {
    mfa_auth_failure = <<-EOT
      aws lambda invoke \
        --function-name ${aws_lambda_function.simulator.function_name} \
        --payload '{"scenario": "mfa_auth_failure", "user": "test-user"}' \
        --cli-binary-format raw-in-base64-out \
        response.json && cat response.json
    EOT
    
    rate_limiting = <<-EOT
      aws lambda invoke \
        --function-name ${aws_lambda_function.simulator.function_name} \
        --payload '{"scenario": "rate_limiting", "user": "test-user"}' \
        --cli-binary-format raw-in-base64-out \
        response.json && cat response.json
    EOT
    
    policy_mismatch = <<-EOT
      aws lambda invoke \
        --function-name ${aws_lambda_function.simulator.function_name} \
        --payload '{"scenario": "policy_mismatch", "user": "test-user"}' \
        --cli-binary-format raw-in-base64-out \
        response.json && cat response.json
    EOT
  }
}

output "useful_links" {
  description = "AWS Console links"
  value = {
    dashboard      = "https://${local.region}.console.aws.amazon.com/cloudwatch/home?region=${local.region}#dashboards:name=${aws_cloudwatch_dashboard.incidents.dashboard_name}"
    dynamodb_table = "https://${local.region}.console.aws.amazon.com/dynamodbv2/home?region=${local.region}#table?name=${aws_dynamodb_table.incidents.name}"
    lambda_simulator = "https://${local.region}.console.aws.amazon.com/lambda/home?region=${local.region}#/functions/${aws_lambda_function.simulator.function_name}"
    lambda_responder = "https://${local.region}.console.aws.amazon.com/lambda/home?region=${local.region}#/functions/${aws_lambda_function.responder.function_name}"
    sns_topic = "https://${local.region}.console.aws.amazon.com/sns/v3/home?region=${local.region}#/topic/${aws_sns_topic.incidents.arn}"
  }
}

