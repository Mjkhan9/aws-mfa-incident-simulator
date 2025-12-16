"""
MFA Incident Simulator

Generates realistic MFA authentication failure events for testing
detection pipelines and incident response procedures.

Scenarios:
1. MFA authentication failure (consistent with token expiration)
2. Rate limiting / account lockout
3. Policy mismatch (MFA present but action denied)
"""

import json
import boto3
import uuid
import time
from datetime import datetime, timezone
from typing import Dict, Any

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')
cloudwatch = boto3.client('cloudwatch')

# Environment variables (set via Terraform)
import os
TABLE_NAME = os.environ.get('INCIDENTS_TABLE', 'mfa-incidents')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main handler for incident simulation.
    
    Event format:
    {
        "scenario": "mfa_auth_failure" | "rate_limiting" | "policy_mismatch",
        "user": "username",
        "source_ip": "optional-ip-address",
        "metadata": { ... optional additional context ... }
    }
    """
    scenario = event.get('scenario', 'mfa_auth_failure')
    user = event.get('user', 'test-user')
    source_ip = event.get('source_ip', '192.0.2.1')  # TEST-NET-1 per RFC 5737
    metadata = event.get('metadata', {})
    
    # Generate incident based on scenario
    if scenario == 'mfa_auth_failure':
        incident = simulate_mfa_auth_failure(user, source_ip, metadata)
    elif scenario == 'rate_limiting':
        incident = simulate_rate_limiting(user, source_ip, metadata)
    elif scenario == 'policy_mismatch':
        incident = simulate_policy_mismatch(user, source_ip, metadata)
    else:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': f'Unknown scenario: {scenario}',
                'valid_scenarios': ['mfa_auth_failure', 'rate_limiting', 'policy_mismatch']
            })
        }
    
    # Store incident in DynamoDB
    store_incident(incident)
    
    # Publish to SNS for alerting
    publish_alert(incident)
    
    # Emit CloudWatch metric
    emit_metric(incident)
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'incident_id': incident['incident_id'],
            'scenario': scenario,
            'status': 'created',
            'timestamp': incident['timestamp']
        })
    }


def simulate_mfa_auth_failure(user: str, source_ip: str, metadata: Dict) -> Dict[str, Any]:
    """
    Simulate MFA authentication failure consistent with token expiration.
    
    Detection signal:
    - ConsoleLogin event with MFAUsed = "No"
    - errorMessage = "Failed authentication"
    """
    incident_id = f"MFA-AUTH-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()
    
    return {
        'incident_id': incident_id,
        'scenario': 'mfa_auth_failure',
        'severity': 'MEDIUM',
        'status': 'OPEN',
        'timestamp': timestamp,
        'created_at': int(time.time()),
        'user': user,
        'source_ip': source_ip,
        'detection_signal': {
            'event_name': 'ConsoleLogin',
            'event_source': 'signin.amazonaws.com',
            'error_message': 'Failed authentication',
            'additional_event_data': {
                'MFAUsed': 'No',
                'LoginTo': 'https://console.aws.amazon.com/console/home',
                'MobileVersion': 'No'
            }
        },
        'description': f'MFA authentication failure for user {user} consistent with token expiration or timing issue',
        'recommended_action': 'User must re-authenticate with valid MFA token',
        'auto_remediation': False,
        'metadata': metadata,
        'environment': ENVIRONMENT,
        'ttl': int(time.time()) + (7 * 24 * 60 * 60)  # 7 day retention
    }


def simulate_rate_limiting(user: str, source_ip: str, metadata: Dict) -> Dict[str, Any]:
    """
    Simulate rate limiting / account lockout scenario.
    
    Detection signal:
    - 5+ ConsoleLogin failures within 60-second window
    - Same userIdentity.userName
    - Same sourceIPAddress
    """
    incident_id = f"RATE-LIMIT-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()
    
    # Simulate failure count
    failure_count = metadata.get('failure_count', 5)
    window_seconds = metadata.get('window_seconds', 60)
    
    return {
        'incident_id': incident_id,
        'scenario': 'rate_limiting',
        'severity': 'HIGH',
        'status': 'OPEN',
        'timestamp': timestamp,
        'created_at': int(time.time()),
        'user': user,
        'source_ip': source_ip,
        'detection_signal': {
            'event_name': 'ConsoleLogin',
            'event_source': 'signin.amazonaws.com',
            'failure_count': failure_count,
            'window_seconds': window_seconds,
            'pattern': 'Multiple failed attempts from same user and IP'
        },
        'description': f'Rate limiting triggered: {failure_count} failed MFA attempts in {window_seconds}s for user {user}',
        'recommended_action': 'Wait for cooldown period, then attempt re-authentication',
        'auto_remediation': True,
        'remediation_type': 'assisted',
        'cooldown_seconds': 300,  # 5 minute cooldown
        'metadata': metadata,
        'environment': ENVIRONMENT,
        'ttl': int(time.time()) + (7 * 24 * 60 * 60)
    }


def simulate_policy_mismatch(user: str, source_ip: str, metadata: Dict) -> Dict[str, Any]:
    """
    Simulate policy mismatch - MFA present but action denied.
    
    Detection signal:
    - errorCode = "AccessDenied"
    - Condition evaluated against aws:MultiFactorAuthPresent
    """
    incident_id = f"POLICY-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()
    
    denied_action = metadata.get('denied_action', 's3:GetObject')
    resource = metadata.get('resource', 'arn:aws:s3:::sensitive-bucket/*')
    
    return {
        'incident_id': incident_id,
        'scenario': 'policy_mismatch',
        'severity': 'MEDIUM',
        'status': 'OPEN',
        'timestamp': timestamp,
        'created_at': int(time.time()),
        'user': user,
        'source_ip': source_ip,
        'detection_signal': {
            'event_name': denied_action.split(':')[1] if ':' in denied_action else denied_action,
            'event_source': f"{denied_action.split(':')[0]}.amazonaws.com" if ':' in denied_action else 'aws.amazonaws.com',
            'error_code': 'AccessDenied',
            'error_message': 'User has MFA but policy condition denies action',
            'condition_evaluated': 'aws:MultiFactorAuthPresent',
            'condition_result': 'false (expected true)',
            'attempted_action': denied_action,
            'resource': resource
        },
        'description': f'Policy mismatch: User {user} has MFA session but {denied_action} denied due to condition mismatch',
        'recommended_action': 'Admin must review IAM policy conditions for aws:MultiFactorAuthPresent',
        'auto_remediation': False,
        'metadata': metadata,
        'environment': ENVIRONMENT,
        'ttl': int(time.time()) + (7 * 24 * 60 * 60)
    }


def store_incident(incident: Dict[str, Any]) -> None:
    """Store incident in DynamoDB."""
    try:
        table = dynamodb.Table(TABLE_NAME)
        table.put_item(Item=incident)
        print(f"[INFO] Stored incident {incident['incident_id']} in DynamoDB")
    except Exception as e:
        print(f"[ERROR] Failed to store incident: {str(e)}")
        raise


def publish_alert(incident: Dict[str, Any]) -> None:
    """Publish incident alert to SNS topic."""
    if not SNS_TOPIC_ARN:
        print("[WARN] SNS_TOPIC_ARN not configured, skipping alert")
        return
    
    try:
        message = {
            'incident_id': incident['incident_id'],
            'scenario': incident['scenario'],
            'severity': incident['severity'],
            'user': incident['user'],
            'description': incident['description'],
            'timestamp': incident['timestamp'],
            'recommended_action': incident['recommended_action']
        }
        
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[{incident['severity']}] MFA Incident: {incident['scenario']}",
            Message=json.dumps(message, indent=2)
        )
        print(f"[INFO] Published alert for incident {incident['incident_id']}")
    except Exception as e:
        print(f"[ERROR] Failed to publish alert: {str(e)}")


def emit_metric(incident: Dict[str, Any]) -> None:
    """Emit CloudWatch metric for dashboard."""
    try:
        cloudwatch.put_metric_data(
            Namespace='MFAIncidentSimulator',
            MetricData=[
                {
                    'MetricName': 'IncidentCount',
                    'Dimensions': [
                        {'Name': 'Scenario', 'Value': incident['scenario']},
                        {'Name': 'Severity', 'Value': incident['severity']},
                        {'Name': 'Environment', 'Value': ENVIRONMENT}
                    ],
                    'Value': 1,
                    'Unit': 'Count'
                }
            ]
        )
        print(f"[INFO] Emitted metric for incident {incident['incident_id']}")
    except Exception as e:
        print(f"[ERROR] Failed to emit metric: {str(e)}")


# For local testing
if __name__ == '__main__':
    # Test each scenario
    test_events = [
        {'scenario': 'mfa_auth_failure', 'user': 'test-user-1'},
        {'scenario': 'rate_limiting', 'user': 'test-user-2', 'metadata': {'failure_count': 7}},
        {'scenario': 'policy_mismatch', 'user': 'test-user-3', 'metadata': {'denied_action': 'ec2:StartInstances'}}
    ]
    
    for event in test_events:
        print(f"\n--- Testing scenario: {event['scenario']} ---")
        # In local testing, we just print the incident structure
        if event['scenario'] == 'mfa_auth_failure':
            incident = simulate_mfa_auth_failure(event['user'], '192.0.2.1', event.get('metadata', {}))
        elif event['scenario'] == 'rate_limiting':
            incident = simulate_rate_limiting(event['user'], '192.0.2.1', event.get('metadata', {}))
        else:
            incident = simulate_policy_mismatch(event['user'], '192.0.2.1', event.get('metadata', {}))
        
        print(json.dumps(incident, indent=2, default=str))

