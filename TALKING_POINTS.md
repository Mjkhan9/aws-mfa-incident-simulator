# Interview Talking Points

Verbatim-ready narratives for discussing this project in interviews.

---

## The 30-Second Pitch

> "I built a dual-mode incident detection system for MFA authentication failures. It can either process real CloudTrail events through EventBridge for live detection, or accept test payloads for demos. It handles token issues, rate limiting, and policy misconfigurations—and I documented the full detection-to-resolution workflow for each. The goal wasn't just infrastructure; it was demonstrating I can operate systems, read logs, and debug systematically."

---

## The 2-Minute Deep Dive

> "In production, MFA failures are one of the most common support tickets. I wanted to build something that shows I understand the operational side—not just deploying resources, but knowing what happens when things break.
>
> The simulator creates three types of incidents:
>
> 1. **MFA authentication failures consistent with token expiration**—where the user's TOTP code is stale or timed out
> 2. **Rate limiting scenarios**—multiple failed attempts triggering lockouts
> 3. **Policy mismatches**—where MFA is present but the IAM policy still denies access due to condition issues
>
> For each one, I built detection using EventBridge rules on CloudTrail, logged incidents to DynamoDB, and set up SNS alerting. I also wrote CloudWatch Insights queries for post-hoc investigation.
>
> The key learning was understanding what AWS actually emits. For example, AWS doesn't explicitly say 'token expired'—you have to detect the pattern: failed login with MFA marked as unused, sometimes following a successful MFA session. That precision matters in interviews and in production."

---

## Anticipated Questions & Answers

### Q: "Can you demo this detecting a real failed login right now?"

> "Yes—the Lambda is dual-mode. It accepts both real CloudTrail events from EventBridge and manual test payloads. In my dev account, I typically trigger it manually for demos to avoid generating noise in CloudTrail. But the EventBridge rules are connected and enabled, so if you fail a login in the console, EventBridge will route it to the Lambda and you'll see a new incident in DynamoDB within a minute or two. The CloudTrail-to-EventBridge path has some latency—usually 1-5 minutes—which is why I also have the manual trigger for quick demos."

---

### Q: "How do you handle the delay in CloudTrail events?"

> "CloudTrail events delivered via EventBridge are near-real-time—typically under a minute for management events, though there can be delays up to 5-15 minutes in some cases. For true real-time blocking, you'd need preventative controls like SCPs or session policies that don't rely on reactive detection. This system is designed for detection and response, not prevention. In an interview context, I'd clarify that EventBridge is faster than S3 delivery of CloudTrail logs, but it's still reactive."

---

### Q: "Why did you choose these three scenarios?"

> "They cover the three main categories I'd see in a real support queue: user error (token timing), security controls working as intended (rate limiting), and configuration problems (policy mismatch). Each requires a different response—user action, waiting for cooldown, or admin intervention. That variety shows I understand the operational landscape."

---

### Q: "How does the auto-remediation work?"

> "I implemented *assisted* remediation, not autonomous healing. For the rate limiting scenario, after the cooldown period, the system updates the incident state in DynamoDB, sends an SNS notification that the lockout has cleared, and logs the resolution time. It doesn't modify IAM directly—that would require safeguards around blast radius, remediation loops, and proper authorization that are beyond the scope of a portfolio project. I'd be happy to discuss what those production safeguards would look like."

---

### Q: "What prevents remediation loops or accidental lockouts?"

> "Great question. In this implementation, the responder Lambda only updates incident *state*—it doesn't touch IAM users or policies. In a production system, you'd need:
> - Rate limiting on the remediation function itself
> - A circuit breaker pattern to stop after N consecutive failures
> - Human approval gates for destructive actions
> - Audit logging of every remediation attempt
>
> I scoped this project to show the workflow, not to build production-grade automation."

---

### Q: "How do you detect MFA token expiration specifically?"

> "AWS doesn't emit an explicit 'token expired' event. What you can detect is a ConsoleLogin failure where `additionalEventData.MFAUsed` is `No` and the error message indicates failed authentication. If you also see a successful MFA login from the same user within a short prior window, that pattern is *consistent with* token expiration—but I'm careful not to claim causation. The user could have typed the wrong code, or there could be clock drift. The detection signal is the same either way."

---

### Q: "What's the MTTR you achieved?"

> "I measured simulated resolution time within the workflow—the delta between incident creation and state update in DynamoDB. For the rate limiting scenario, that's typically the cooldown period plus processing time. I want to be clear: this is relative MTTR within my test environment, not a production SLA. In a real org, you'd measure against actual ticket resolution and include human response time."

---

### Q: "Why not more scenarios?"

> "Scope discipline. I had five scenarios planned—including impossible travel and device compliance—but three clean, well-documented scenarios are more valuable than five half-finished ones. I can describe the detection logic for the others, but I prioritized depth over breadth. That's how I'd approach a real sprint too."

---

### Q: "What would you add for production?"

> "Several things:
> - **Step Functions** to orchestrate the response workflow with retries and human approval gates
> - **AWS Config rules** to continuously validate MFA policy compliance
> - **Integration with a ticketing system** like ServiceNow or Jira
> - **Runbook automation** using SSM documents
> - **Multi-account support** via Organizations and delegated admin
>
> But those are extensions—the core detection and response pattern is what I wanted to demonstrate."

---

## Red Flags to Avoid

| Don't Say | Say Instead |
|-----------|-------------|
| "Self-healing MFA incidents" | "Assisted remediation for low-risk scenarios" |
| "Detects token expiration" | "Detects patterns consistent with token expiration" |
| "Production MTTR of X seconds" | "Simulated resolution time within the workflow" |
| "Fully automated response" | "Constrained auto-response with explicit safeguards" |
| "I built 5 scenarios" (if only 3 are complete) | "I built 3 scenarios with 2 more planned as extensions" |

---

## The Closer

> "This project shows I can think operationally. I understand that building infrastructure is only half the job—the other half is knowing what breaks, how to detect it, and how to respond systematically. That's what I'd bring to a support or operations role."

