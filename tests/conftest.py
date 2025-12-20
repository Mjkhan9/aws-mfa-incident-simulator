"""
Pytest fixtures for MFA Incident Simulator tests.

Uses moto to mock AWS services:
- DynamoDB (incident storage)
- SNS (alerting)
- CloudWatch (metrics)

This allows testing Lambda logic without hitting real AWS.
"""

import os
import pytest
import boto3
from moto import mock_aws


# Set environment variables BEFORE importing handler
@pytest.fixture(scope="session", autouse=True)
def set_env_vars():
    """Set required environment variables for all tests."""
    os.environ["INCIDENTS_TABLE"] = "test-mfa-incidents"
    os.environ["SNS_TOPIC_ARN"] = "arn:aws:sns:us-east-1:123456789012:test-alerts"
    os.environ["ENVIRONMENT"] = "test"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"


@pytest.fixture
def aws_credentials():
    """Mocked AWS credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def mock_dynamodb(aws_credentials):
    """Create mocked DynamoDB table for incident storage."""
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        
        # Create the incidents table matching Terraform schema
        table = dynamodb.create_table(
            TableName="test-mfa-incidents",
            KeySchema=[
                {"AttributeName": "incident_id", "KeyType": "HASH"}
            ],
            AttributeDefinitions=[
                {"AttributeName": "incident_id", "AttributeType": "S"},
                {"AttributeName": "scenario", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"}
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "scenario-created-index",
                    "KeySchema": [
                        {"AttributeName": "scenario", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"}
                    ],
                    "Projection": {"ProjectionType": "ALL"}
                }
            ],
            BillingMode="PAY_PER_REQUEST"
        )
        
        # Wait for table to be active
        table.meta.client.get_waiter("table_exists").wait(TableName="test-mfa-incidents")
        
        yield dynamodb


@pytest.fixture
def mock_sns(aws_credentials):
    """Create mocked SNS topic for alerts."""
    with mock_aws():
        sns = boto3.client("sns", region_name="us-east-1")
        
        # Create the alerts topic
        response = sns.create_topic(Name="test-alerts")
        topic_arn = response["TopicArn"]
        
        yield sns, topic_arn


@pytest.fixture
def mock_cloudwatch(aws_credentials):
    """Create mocked CloudWatch for metrics."""
    with mock_aws():
        cloudwatch = boto3.client("cloudwatch", region_name="us-east-1")
        yield cloudwatch


@pytest.fixture
def mock_all_aws(aws_credentials):
    """
    Mock all AWS services needed by the handler.
    Use this for integration-style tests.
    """
    with mock_aws():
        # DynamoDB
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="test-mfa-incidents",
            KeySchema=[
                {"AttributeName": "incident_id", "KeyType": "HASH"}
            ],
            AttributeDefinitions=[
                {"AttributeName": "incident_id", "AttributeType": "S"},
                {"AttributeName": "scenario", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"}
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "scenario-created-index",
                    "KeySchema": [
                        {"AttributeName": "scenario", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"}
                    ],
                    "Projection": {"ProjectionType": "ALL"}
                }
            ],
            BillingMode="PAY_PER_REQUEST"
        )
        table.meta.client.get_waiter("table_exists").wait(TableName="test-mfa-incidents")
        
        # SNS
        sns = boto3.client("sns", region_name="us-east-1")
        sns.create_topic(Name="test-alerts")
        
        # CloudWatch
        cloudwatch = boto3.client("cloudwatch", region_name="us-east-1")
        
        yield {
            "dynamodb": dynamodb,
            "sns": sns,
            "cloudwatch": cloudwatch,
            "table": table
        }


# =============================================================================
# CloudTrail Event Fixtures - Realistic test data
# =============================================================================

@pytest.fixture
def cloudtrail_console_login_success_no_mfa():
    """
    Realistic CloudTrail event: Successful console login WITHOUT MFA.
    This is a security concern - user logged in but MFA was not enforced.
    """
    return {
        "detail-type": "AWS Console Sign In via CloudTrail",
        "source": "aws.signin",
        "detail": {
            "eventVersion": "1.08",
            "eventTime": "2025-02-18T14:32:11Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.42",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "responseElements": {
                "ConsoleLogin": "Success"
            },
            "additionalEventData": {
                "MFAUsed": "No",
                "LoginTo": "https://console.aws.amazon.com/console/home?region=us-east-1",
                "MobileVersion": "No"
            },
            "userIdentity": {
                "type": "IAMUser",
                "userName": "finance-analyst-01",
                "accountId": "123456789012",
                "principalId": "AIDAEXAMPLE123456789",
                "arn": "arn:aws:iam::123456789012:user/finance-analyst-01"
            },
            "eventID": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
            "readOnly": False,
            "eventType": "AwsConsoleSignIn",
            "managementEvent": True,
            "recipientAccountId": "123456789012"
        }
    }


@pytest.fixture
def cloudtrail_console_login_failed_no_mfa():
    """
    Realistic CloudTrail event: Failed console login with MFA issue.
    User attempted login but authentication failed.
    """
    return {
        "detail-type": "AWS Console Sign In via CloudTrail",
        "source": "aws.signin",
        "detail": {
            "eventVersion": "1.08",
            "eventTime": "2025-02-18T14:30:45Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.42",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "errorMessage": "Failed authentication",
            "responseElements": {
                "ConsoleLogin": "Failure"
            },
            "additionalEventData": {
                "MFAUsed": "No",
                "LoginTo": "https://console.aws.amazon.com/console/home?region=us-east-1",
                "MobileVersion": "No"
            },
            "userIdentity": {
                "type": "IAMUser",
                "userName": "dev-engineer-02",
                "accountId": "123456789012",
                "principalId": "AIDAEXAMPLE123456790",
                "arn": "arn:aws:iam::123456789012:user/dev-engineer-02"
            },
            "eventID": "a1b2c3d4-5678-90ab-cdef-EXAMPLE22222",
            "readOnly": False,
            "eventType": "AwsConsoleSignIn",
            "managementEvent": True,
            "recipientAccountId": "123456789012"
        }
    }


@pytest.fixture
def cloudtrail_console_login_success_with_mfa():
    """
    Realistic CloudTrail event: Successful console login WITH MFA.
    This should NOT trigger an incident - it's the expected behavior.
    """
    return {
        "detail-type": "AWS Console Sign In via CloudTrail",
        "source": "aws.signin",
        "detail": {
            "eventVersion": "1.08",
            "eventTime": "2025-02-18T14:35:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "198.51.100.10",
            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "responseElements": {
                "ConsoleLogin": "Success"
            },
            "additionalEventData": {
                "MFAUsed": "Yes",
                "LoginTo": "https://console.aws.amazon.com/console/home?region=us-east-1",
                "MobileVersion": "No"
            },
            "userIdentity": {
                "type": "IAMUser",
                "userName": "security-admin-01",
                "accountId": "123456789012",
                "principalId": "AIDAEXAMPLE123456791",
                "arn": "arn:aws:iam::123456789012:user/security-admin-01"
            },
            "eventID": "a1b2c3d4-5678-90ab-cdef-EXAMPLE33333",
            "readOnly": False,
            "eventType": "AwsConsoleSignIn",
            "managementEvent": True,
            "recipientAccountId": "123456789012"
        }
    }


@pytest.fixture
def cloudtrail_access_denied_with_mfa():
    """
    Realistic CloudTrail event: AccessDenied despite having MFA session.
    This indicates a policy mismatch - user has MFA but policy denies.
    """
    return {
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.s3",
        "detail": {
            "eventVersion": "1.09",
            "eventTime": "2025-02-18T15:00:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.55",
            "userAgent": "aws-cli/2.13.0 Python/3.11.4",
            "errorCode": "AccessDenied",
            "errorMessage": "Access Denied",
            "requestParameters": {
                "bucketName": "sensitive-financial-data",
                "key": "reports/q4-2024.pdf"
            },
            "userIdentity": {
                "type": "IAMUser",
                "userName": "finance-analyst-01",
                "accountId": "123456789012",
                "principalId": "AIDAEXAMPLE123456789",
                "arn": "arn:aws:iam::123456789012:user/finance-analyst-01",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true",
                        "creationDate": "2025-02-18T14:32:11Z"
                    }
                }
            },
            "eventID": "a1b2c3d4-5678-90ab-cdef-EXAMPLE44444",
            "readOnly": True,
            "eventType": "AwsApiCall",
            "managementEvent": False,
            "recipientAccountId": "123456789012"
        }
    }


@pytest.fixture
def cloudtrail_access_denied_without_mfa():
    """
    Realistic CloudTrail event: AccessDenied without MFA session.
    This should NOT trigger policy_mismatch - expected denial.
    """
    return {
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.s3",
        "detail": {
            "eventVersion": "1.09",
            "eventTime": "2025-02-18T15:05:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.60",
            "userAgent": "aws-cli/2.13.0 Python/3.11.4",
            "errorCode": "AccessDenied",
            "errorMessage": "Access Denied",
            "requestParameters": {
                "bucketName": "sensitive-financial-data",
                "key": "reports/q4-2024.pdf"
            },
            "userIdentity": {
                "type": "IAMUser",
                "userName": "contractor-01",
                "accountId": "123456789012",
                "principalId": "AIDAEXAMPLE123456792",
                "arn": "arn:aws:iam::123456789012:user/contractor-01",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "false",
                        "creationDate": "2025-02-18T15:00:00Z"
                    }
                }
            },
            "eventID": "a1b2c3d4-5678-90ab-cdef-EXAMPLE55555",
            "readOnly": True,
            "eventType": "AwsApiCall",
            "managementEvent": False,
            "recipientAccountId": "123456789012"
        }
    }


# =============================================================================
# Rate Limiting Burst Fixtures
# =============================================================================

@pytest.fixture
def cloudtrail_burst_5_failures_60s():
    """
    Generate 5 failed login events within 60 seconds.
    This represents a rate-limiting trigger pattern.
    """
    base_event = {
        "detail-type": "AWS Console Sign In via CloudTrail",
        "source": "aws.signin",
        "detail": {
            "eventVersion": "1.08",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.100",
            "userAgent": "Mozilla/5.0",
            "errorMessage": "Failed authentication",
            "responseElements": {"ConsoleLogin": "Failure"},
            "additionalEventData": {"MFAUsed": "No"},
            "userIdentity": {
                "type": "IAMUser",
                "userName": "brute-force-target",
                "accountId": "123456789012"
            }
        }
    }
    
    events = []
    for i in range(5):
        event = base_event.copy()
        event["detail"] = base_event["detail"].copy()
        event["detail"]["eventTime"] = f"2025-02-18T14:30:{10 + i * 10:02d}Z"
        event["detail"]["eventID"] = f"burst-event-{i+1}"
        events.append(event)
    
    return events

