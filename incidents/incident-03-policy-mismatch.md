# Incident Runbook: Policy Mismatch (MFA Present but Action Denied)

**Scenario:** User has valid MFA session but IAM policy denies action  
**Severity:** MEDIUM  
**Auto-Remediation:** No (admin intervention required)

---

## Overview

User authenticates successfully with MFA, but when attempting an action, receives `AccessDenied`. The IAM policy has a condition that isn't being satisfied, even though MFA was used.

Common causes:
- Policy requires `aws:MultiFactorAuthPresent` but condition evaluates incorrectly
- Policy requires `aws:MultiFactorAuthAge` and session is too old
- Policy uses `Bool` condition incorrectly (string vs boolean)
- Policy attached to wrong principal

---

## Detection Signal

### CloudTrail Event Pattern

```json
{
  "eventName": "<attempted-action>",
  "eventSource": "<service>.amazonaws.com",
  "errorCode": "AccessDenied",
  "errorMessage": "User: arn:aws:iam::123456789012:user/<user> is not authorized to perform: <action>",
  "userIdentity": {
    "userName": "<affected-user>",
    "sessionContext": {
      "attributes": {
        "mfaAuthenticated": "true"
      }
    }
  }
}
```

### CloudWatch Insights Query

```sql
fields @timestamp, userIdentity.userName, eventName, eventSource, errorCode, errorMessage
| filter errorCode = "AccessDenied"
| filter userIdentity.sessionContext.attributes.mfaAuthenticated = "true"
| sort @timestamp desc
| limit 50
```

---

## Investigation Steps

### Step 1: Confirm MFA was used in session

```sql
fields @timestamp, userIdentity.userName, 
       userIdentity.sessionContext.attributes.mfaAuthenticated,
       eventName, errorCode
| filter userIdentity.userName = "<affected-user>"
| filter errorCode = "AccessDenied"
| sort @timestamp desc
| limit 20
```

If `mfaAuthenticated = "true"` but action denied, this is a policy mismatch.

### Step 2: Identify the denying policy

```bash
# Simulate the policy evaluation
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<account-id>:user/<affected-user> \
  --action-names <denied-action> \
  --resource-arns <resource-arn> \
  --context-entries "ContextKeyName=aws:MultiFactorAuthPresent,ContextKeyValues=true,ContextKeyType=boolean"
```

Expected output shows which policy statement caused the denial.

### Step 3: Retrieve and analyze the policy

```bash
# List user's attached policies
aws iam list-attached-user-policies --user-name <affected-user>

# Get policy document
aws iam get-policy-version \
  --policy-arn <policy-arn> \
  --version-id <version>
```

### Step 4: Check for common condition mistakes

**Common Issue 1: String vs Boolean**
```json
// WRONG - uses string comparison
"Condition": {
  "StringEquals": {
    "aws:MultiFactorAuthPresent": "true"
  }
}

// CORRECT - uses boolean comparison
"Condition": {
  "Bool": {
    "aws:MultiFactorAuthPresent": "true"
  }
}
```

**Common Issue 2: Session Age**
```json
// This denies if MFA session older than 1 hour (3600 seconds)
"Condition": {
  "NumericLessThan": {
    "aws:MultiFactorAuthAge": "3600"
  }
}
```

---

## Resolution

### Fix the IAM Policy

1. **Identify incorrect condition syntax**
2. **Update policy with correct condition**
3. **Test with policy simulator**

```bash
# Create new policy version with fix
aws iam create-policy-version \
  --policy-arn <policy-arn> \
  --policy-document file://corrected-policy.json \
  --set-as-default
```

### Corrected Policy Example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireMFA",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::sensitive-bucket/*",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
```

### Verification

```bash
# Re-run policy simulation
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<account-id>:user/<affected-user> \
  --action-names <action> \
  --resource-arns <resource> \
  --context-entries "ContextKeyName=aws:MultiFactorAuthPresent,ContextKeyValues=true,ContextKeyType=boolean"

# Expected: "EvalDecision": "allowed"
```

---

## Escalation Criteria

Escalate to Cloud Security team if:
- [ ] Policy change requires CAB approval
- [ ] Multiple users affected by same policy
- [ ] Unclear which policy is causing denial
- [ ] Policy is managed by AWS Organizations SCP

---

## Post-Incident

### Documentation

- [ ] Record incident in DynamoDB
- [ ] Document which policy was incorrect
- [ ] Note the fix applied
- [ ] Update any IaC (Terraform) to prevent regression

### Prevention

- Use Terraform/IaC for policy management
- Implement policy validation in CI/CD
- Use AWS IAM Access Analyzer for policy checking
- Document MFA requirements in runbooks

---

## Console Evidence

| Evidence | Location |
|----------|----------|
| Incident records with policy mismatch details | `screenshots/dynamodb-incidents.png` |
| EventBridge rule for AccessDenied detection | `screenshots/eventbridge-rules.png` |

Each policy mismatch incident in DynamoDB includes the `detection_signal` with:
- `attempted_action` - The action that was denied
- `condition_evaluated` - The IAM condition that failed (`aws:MultiFactorAuthPresent`)
- `resource` - The target resource ARN

---

## Interview Talking Point

> "Policy mismatch is one of the trickiest MFA issues because the user did everything right—they authenticated with MFA—but the policy condition isn't satisfied. I've seen this with StringEquals vs Bool conditions, and with MultiFactorAuthAge requirements. The fix is straightforward once you identify it, but the investigation requires understanding how IAM condition operators work. I use the policy simulator to verify before and after the fix."

---

*Last Updated: December 2025*

