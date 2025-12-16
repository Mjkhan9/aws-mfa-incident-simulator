-- CloudWatch Insights Query: Rate Limiting Detection
-- Detects multiple failed login attempts suggesting rate limiting

-- Core detection: 5+ failures in 5-minute window
fields @timestamp, userIdentity.userName, sourceIPAddress, errorMessage
| filter eventName = "ConsoleLogin"
| filter ispresent(errorMessage)
| stats count(*) as failure_count by userIdentity.userName, sourceIPAddress, bin(5m)
| filter failure_count >= 5
| sort failure_count desc

-- Detailed timeline for specific user
-- fields @timestamp, userIdentity.userName, sourceIPAddress, userAgent, errorMessage
-- | filter eventName = "ConsoleLogin"
-- | filter userIdentity.userName = "<specific-user>"
-- | filter ispresent(errorMessage)
-- | sort @timestamp asc
-- | limit 50

-- Geographic analysis (for impossible travel correlation)
-- fields @timestamp, userIdentity.userName, sourceIPAddress
-- | filter eventName = "ConsoleLogin"
-- | filter ispresent(errorMessage)
-- | stats count(*) as attempts, 
--         earliest(@timestamp) as first_attempt, 
--         latest(@timestamp) as last_attempt 
--   by userIdentity.userName, sourceIPAddress
-- | filter attempts >= 3
-- | sort attempts desc

