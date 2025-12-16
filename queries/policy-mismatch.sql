-- CloudWatch Insights Query: Policy Mismatch Detection
-- Detects AccessDenied when user has active MFA session

-- Core detection: AccessDenied with MFA authenticated
fields @timestamp, userIdentity.userName, eventName, eventSource, errorCode, errorMessage
| filter errorCode = "AccessDenied"
| filter userIdentity.sessionContext.attributes.mfaAuthenticated = "true"
| sort @timestamp desc
| limit 50

-- Breakdown by action (to identify problematic policies)
-- fields @timestamp, userIdentity.userName, eventName, eventSource, errorCode
-- | filter errorCode = "AccessDenied"
-- | filter userIdentity.sessionContext.attributes.mfaAuthenticated = "true"
-- | stats count(*) as denials by eventName, eventSource
-- | sort denials desc

-- User-specific investigation
-- fields @timestamp, eventName, eventSource, errorCode, errorMessage,
--        requestParameters, userIdentity.sessionContext.attributes.mfaAuthenticated
-- | filter userIdentity.userName = "<specific-user>"
-- | filter errorCode = "AccessDenied"
-- | sort @timestamp desc
-- | limit 20

-- Find affected resources
-- fields @timestamp, userIdentity.userName, eventName, 
--        requestParameters.bucketName, requestParameters.key,
--        requestParameters.instanceId
-- | filter errorCode = "AccessDenied"
-- | filter userIdentity.sessionContext.attributes.mfaAuthenticated = "true"
-- | sort @timestamp desc
-- | limit 30

