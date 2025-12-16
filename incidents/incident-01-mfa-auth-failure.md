# Incident Runbook: MFA Authentication Failure

**Scenario:** MFA authentication failure consistent with token expiration  
**Severity:** MEDIUM  
**Auto-Remediation:** No (user action required)

---

## Overview

User attempts console login but MFA validation fails. This pattern is consistent with:
- TOTP token expired (30-second window passed)
- Clock drift between user device and AWS
- User entered incorrect code
- Session timeout during MFA entry

---

## Detection Signal

### CloudTrail Event Pattern

```json
{
  "eventName": "ConsoleLogin",
  "eventSource": "signin.amazonaws.com",
  "errorMessage": "Failed authentication",
  "additionalEventData": {
    "MFAUsed": "No",
    "LoginTo": "https://console.aws.amazon.com/console/home"
  },
  "userIdentity": {
    "userName": "<affected-user>"
  },
  "sourceIPAddress": "<user-ip>"
}
```

### CloudWatch Insights Query

```sql
fields @timestamp, @message, userIdentity.userName, sourceIPAddress
| filter eventName = "ConsoleLogin"
| filter ispresent(errorMessage)
| filter additionalEventData.MFAUsed = "No"
| sort @timestamp desc
| limit 50
```

---

## Investigation Steps

### Step 1: Confirm the failure pattern

```bash
# Query recent console login failures
aws logs start-query \
  --log-group-name "/aws/cloudtrail/<trail-name>" \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, userIdentity.userName, sourceIPAddress, errorMessage
    | filter eventName = "ConsoleLogin" and ispresent(errorMessage)
    | sort @timestamp desc
    | limit 20'
```

### Step 2: Check for prior successful MFA login

If user had successful MFA within the last 15 minutes, this suggests token expiration mid-session rather than persistent issue.

```sql
fields @timestamp, userIdentity.userName, additionalEventData.MFAUsed
| filter eventName = "ConsoleLogin"
| filter userIdentity.userName = "<affected-user>"
| sort @timestamp desc
| limit 10
```

### Step 3: Verify user MFA device status

```bash
aws iam list-mfa-devices --user-name <affected-user>
```

Expected output:
```json
{
  "MFADevices": [
    {
      "UserName": "<affected-user>",
      "SerialNumber": "arn:aws:iam::123456789012:mfa/<affected-user>",
      "EnableDate": "2024-01-15T10:30:00Z"
    }
  ]
}
```

---

## Resolution

### Immediate Action

**User self-service:**
1. Wait 30 seconds for new TOTP code
2. Verify device clock is synchronized
3. Attempt login again with fresh code

**If persistent failures:**
1. User should reset MFA device via account recovery
2. IT admin can deregister and re-register MFA if needed

### CLI Command (Admin intervention)

```bash
# Deactivate existing MFA (requires admin)
aws iam deactivate-mfa-device \
  --user-name <affected-user> \
  --serial-number arn:aws:iam::<account-id>:mfa/<affected-user>

# User must then re-enable MFA via console
```

⚠️ **Caution:** Deactivating MFA removes a security control. Only do this with proper verification of user identity.

---

## Post-Incident

### Documentation

- [ ] Record incident in DynamoDB via simulator
- [ ] Note resolution time
- [ ] Update user if recurring issue

### Prevention

- Recommend users sync device time automatically
- Consider hardware security keys for sensitive accounts
- Implement backup MFA methods

---

## Console Evidence (Screenshots)

| Screenshot | Description |
|------------|-------------|
| `screenshots/cloudtrail-mfa-failure.png` | CloudTrail event showing failed login |
| `screenshots/insights-mfa-query.png` | CloudWatch Insights query results |
| `screenshots/iam-mfa-device.png` | IAM console showing MFA device status |

---

## Interview Talking Point

> "When investigating MFA auth failures, I check CloudTrail for the specific pattern: ConsoleLogin with MFAUsed=No and an error message. AWS doesn't emit 'token expired' explicitly, so I look for the pattern and corroborate with recent successful logins. If the user had a successful MFA session minutes before, that's consistent with token expiration. The resolution is user self-service—I don't touch their MFA device unless absolutely necessary."

---

*Last Updated: December 2024*

