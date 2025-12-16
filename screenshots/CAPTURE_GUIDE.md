# Screenshots Captured

Evidence screenshots from deployed AWS infrastructure.

## Required Screenshots

| Filename | Description | Status |
|----------|-------------|--------|
| `dynamodb-incidents.png` | DynamoDB table with 13 incident records | ✅ |
| `eventbridge-rules.png` | EventBridge rules (all enabled) | ✅ |
| `lambda-function.png` | Lambda function with EventBridge triggers | ✅ |
| `cloudwatch-dashboard.png` | CloudWatch dashboard with 4 widgets | ✅ |
| `sns-topic.png` | SNS topic for incident alerts | ✅ |

## What Each Screenshot Proves

### `dynamodb-incidents.png`
Shows the `mfa-incident-simulator-dev-incidents` table with:
- 13 incident records
- Mix of scenarios: `mfa_auth_failure`, `rate_limiting`, `policy_mismatch`
- Both OPEN and RESOLVED statuses
- `detection_signal` field with CloudTrail event patterns
- Resolution time tracking (544 seconds shown)

### `eventbridge-rules.png`
Shows three project rules all **Enabled**:
- `mfa-incident-simulator-dev-console-login-failure`
- `mfa-incident-simulator-dev-access-denied`
- `mfa-incident-simulator-dev-responder-schedule`

### `lambda-function.png`
Shows the simulator Lambda with:
- EventBridge (CloudWatch Events) trigger connected
- Function overview diagram
- Code deployment

### `cloudwatch-dashboard.png`
Shows `mfa-incident-simulator-dev-dashboard` with 4 widgets:
- Incidents by Type
- Incident Volume
- Simulated Resolution Time
- Recent Incident Activity

### `sns-topic.png`
Shows `mfa-incident-simulator-dev-alerts` SNS topic configured for incident notifications.
