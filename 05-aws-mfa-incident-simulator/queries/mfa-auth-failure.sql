-- CloudWatch Insights Query: MFA Authentication Failure Detection
-- Detects failed console logins consistent with MFA token issues

-- Basic detection query
fields @timestamp, @message, userIdentity.userName, sourceIPAddress, errorMessage
| filter eventName = "ConsoleLogin"
| filter ispresent(errorMessage)
| filter additionalEventData.MFAUsed = "No"
| sort @timestamp desc
| limit 50

-- Aggregated view by user (for pattern detection)
-- fields @timestamp, userIdentity.userName, sourceIPAddress
-- | filter eventName = "ConsoleLogin"
-- | filter ispresent(errorMessage)
-- | filter additionalEventData.MFAUsed = "No"
-- | stats count(*) as failures by userIdentity.userName, bin(1h)
-- | filter failures >= 2
-- | sort failures desc

-- Correlation query: Find users who had success before failure
-- (indicates token expiration vs. never had MFA)
-- fields @timestamp, userIdentity.userName, responseElements.ConsoleLogin, additionalEventData.MFAUsed
-- | filter eventName = "ConsoleLogin"
-- | filter userIdentity.userName = "<specific-user>"
-- | sort @timestamp desc
-- | limit 20

