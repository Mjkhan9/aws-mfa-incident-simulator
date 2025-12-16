# Screenshot Capture Guide

Take these screenshots before ending your lab session.

## Required Screenshots (5 total)

### 1. CloudWatch Dashboard
**URL:** https://us-east-1.console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=mfa-incident-simulator-dev-dashboard

**Save as:** `dashboard-overview.png`

**What to capture:** Full dashboard showing all 4 widgets

---

### 2. DynamoDB Incidents Table
**URL:** https://us-east-1.console.aws.amazon.com/dynamodbv2/home?region=us-east-1#table?name=mfa-incident-simulator-dev-incidents

**Save as:** `dynamodb-incidents.png`

**What to capture:** Table view showing the 3 test incidents

---

### 3. Lambda Simulator Function
**URL:** https://us-east-1.console.aws.amazon.com/lambda/home?region=us-east-1#/functions/mfa-incident-simulator-dev-simulator

**Save as:** `lambda-simulator.png`

**What to capture:** Function overview showing code, configuration, monitoring

---

### 4. EventBridge Rules
**URL:** https://us-east-1.console.aws.amazon.com/events/home?region=us-east-1#/rules

**Save as:** `eventbridge-rules.png`

**What to capture:** List of rules showing mfa-incident-simulator rules

---

### 5. SNS Topic
**URL:** https://us-east-1.console.aws.amazon.com/sns/v3/home?region=us-east-1#/topic/arn:aws:sns:us-east-1:637423174317:mfa-incident-simulator-dev-alerts

**Save as:** `sns-alerts.png`

**What to capture:** Topic details and subscriptions

---

## How to Take Screenshots

**Windows:** Press `Win + Shift + S`, select area, paste into Paint, save as PNG

**Save location:** `aws-mfa-incident-simulator/screenshots/`

---

## After Capturing

Your screenshots folder should contain:
```
screenshots/
├── CAPTURE_GUIDE.md (this file)
├── dashboard-overview.png
├── dynamodb-incidents.png
├── lambda-simulator.png
├── eventbridge-rules.png
└── sns-alerts.png
```

