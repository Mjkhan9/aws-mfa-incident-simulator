# Incident Runbook: Rate Limiting / Account Lockout

**Scenario:** Multiple failed MFA attempts trigger rate limiting  
**Severity:** HIGH  
**Auto-Remediation:** Yes (assisted - state update after cooldown)

---

## Overview

Multiple failed authentication attempts from the same user trigger AWS rate limiting. This is a security control working as intended, but requires operational response.

Common causes:
- User repeatedly entering wrong MFA code
- Automated tool with stale credentials
- Potential brute force attempt (investigate source IP)

---

## Detection Signal

### Pattern Definition

- 5+ failed `ConsoleLogin` events
- Within 60-second rolling window
- Same `userIdentity.userName`
- Same `sourceIPAddress`

### CloudTrail Event Pattern

```json
{
  "eventName": "ConsoleLogin",
  "eventSource": "signin.amazonaws.com",
  "errorMessage": "Failed authentication",
  "userIdentity": {
    "userName": "<affected-user>"
  },
  "sourceIPAddress": "<user-ip>",
  "eventTime": "<timestamp>"
}
```

### CloudWatch Insights Query

```sql
fields @timestamp, userIdentity.userName, sourceIPAddress, errorMessage
| filter eventName = "ConsoleLogin"
| filter ispresent(errorMessage)
| stats count(*) as failure_count by userIdentity.userName, sourceIPAddress, bin(5m)
| filter failure_count >= 5
| sort failure_count desc
```

---

## Investigation Steps

### Step 1: Quantify the failure pattern

```bash
# Count failures by user in last hour
aws logs start-query \
  --log-group-name "/aws/cloudtrail/<trail-name>" \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, userIdentity.userName, sourceIPAddress
    | filter eventName = "ConsoleLogin" and ispresent(errorMessage)
    | stats count(*) as failures by userIdentity.userName, sourceIPAddress
    | filter failures >= 3
    | sort failures desc'
```

### Step 2: Analyze source IP

Determine if this is legitimate user error or potential attack.

```sql
fields @timestamp, sourceIPAddress, userAgent
| filter eventName = "ConsoleLogin"
| filter userIdentity.userName = "<affected-user>"
| filter ispresent(errorMessage)
| sort @timestamp desc
| limit 20
```

Check:
- [ ] Is source IP from known corporate range?
- [ ] Is user agent consistent with browser?
- [ ] Geographic location reasonable?

### Step 3: Check for successful logins after failures

```sql
fields @timestamp, userIdentity.userName, responseElements.ConsoleLogin
| filter eventName = "ConsoleLogin"
| filter userIdentity.userName = "<affected-user>"
| filter responseElements.ConsoleLogin = "Success"
| sort @timestamp desc
| limit 5
```

---

## Resolution

### Assisted Remediation (Automated)

The responder Lambda handles this scenario:

1. Detects incident is past cooldown period (5 minutes default)
2. Updates incident status in DynamoDB to `RESOLVED`
3. Sends SNS notification that lockout has cleared
4. Logs resolution time for metrics

**What it does NOT do:**
- Does not modify IAM user
- Does not unlock any account
- Does not reset credentials

### Manual Steps (If Automated Response Fails)

```bash
# Verify incident status in DynamoDB
aws dynamodb get-item \
  --table-name mfa-incident-simulator-dev-incidents \
  --key '{"incident_id": {"S": "<incident-id>"}}'

# Check Lambda responder logs
aws logs tail /aws/lambda/mfa-incident-simulator-dev-responder --since 30m
```

### User Communication

```
Subject: MFA Login Issue Resolved

Your account was temporarily rate-limited due to multiple failed login 
attempts. The lockout has cleared. Please wait 30 seconds for a fresh 
MFA code before attempting to log in again.

If you did not attempt these logins, please contact IT Security immediately.
```

---

## Escalation Criteria

Escalate to Security team if:
- [ ] Source IP is from unexpected geography
- [ ] Multiple users affected simultaneously
- [ ] Pattern suggests credential stuffing
- [ ] User denies making login attempts

---

## Post-Incident

### Metrics Captured

| Metric | Value |
|--------|-------|
| Incident ID | `<from-dynamodb>` |
| Created At | `<timestamp>` |
| Resolved At | `<timestamp>` |
| Resolution Time | `<seconds>` |
| Remediation Type | `assisted_auto` |

### Dashboard Update

Resolution time is automatically emitted to CloudWatch and appears in the dashboard under "Simulated Resolution Time" widget.

---

## Console Evidence

| Evidence | Location |
|----------|----------|
| Incident records (including RESOLVED status) | `screenshots/dynamodb-incidents.png` |
| SNS topic for alerts | `screenshots/sns-topic.png` |
| CloudWatch dashboard with resolution metrics | `screenshots/cloudwatch-dashboard.png` |

The DynamoDB table shows both OPEN and RESOLVED incidents, with `resolution_time_seconds` populated for resolved rate-limiting events.

---

## Interview Talking Point

> "For rate limiting, I implemented assisted remediation rather than full automation. After the cooldown period, the system updates the incident state, sends a notification, and logs the resolution time—but it doesn't modify IAM. That's intentional. In production, you'd need safeguards around blast radius and remediation loops before doing anything destructive. I wanted to show the workflow without overclaiming capabilities."

---

*Last Updated: December 2025*

