"""
MFA Incident Simulator & Detector

Dual-mode Lambda function:
1. SIMULATOR MODE: Generates synthetic incidents for testing (manual CLI invoke)
2. DETECTOR MODE: Processes real CloudTrail events from EventBridge

Scenarios:
- MFA authentication failure (consistent with token expiration)
- Rate limiting / account lockout
- Policy mismatch (MFA present but action denied)
"""

import json
import boto3
import uuid
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional

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
    Main handler supporting both simulator and detector modes.
    
    Simulator Mode (manual invoke):
    {
        "scenario": "mfa_auth_failure" | "rate_limiting" | "policy_mismatch",
        "user": "username",
        ...
    }
    
    Detector Mode (EventBridge from CloudTrail):
    {
        "detail-type": "AWS Console Sign In via CloudTrail",
        "detail": { ... CloudTrail event ... }
    }
    """
    
    # Determine mode based on event structure
    if is_cloudtrail_event(event):
        return process_cloudtrail_event(event)
    else:
        return process_simulator_event(event)


def is_cloudtrail_event(event: Dict[str, Any]) -> bool:
    """Check if this is a real CloudTrail event from EventBridge."""
    return (
        'detail-type' in event and 
        'detail' in event and
        isinstance(event.get('detail'), dict)
    )


def process_cloudtrail_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process real CloudTrail events from EventBridge.
    
    Detects:
    - ConsoleLogin failures (MFA auth failure pattern)
    - AccessDenied errors (policy mismatch pattern)
    """
    detail_type = event.get('detail-type', '')
    detail = event.get('detail', {})
    
    print(f"[INFO] Processing CloudTrail event: {detail_type}")
    
    # Extract common fields
    event_name = detail.get('eventName', '')
    error_code = detail.get('errorCode', '')
    error_message = detail.get('errorMessage', '')
    user_identity = detail.get('userIdentity', {})
    username = user_identity.get('userName', user_identity.get('principalId', 'unknown'))
    source_ip = detail.get('sourceIPAddress', 'unknown')
    
    incident = None
    
    # Pattern 1: Console Login Failure (MFA auth failure)
    if event_name == 'ConsoleLogin' and error_message:
        additional_data = detail.get('additionalEventData', {})
        mfa_used = additional_data.get('MFAUsed', 'Yes')
        
        if mfa_used == 'No' or error_message:
            incident = create_mfa_auth_failure_incident(
                user=username,
                source_ip=source_ip,
                cloudtrail_detail=detail
            )
    
    # Pattern 2: AccessDenied (Policy mismatch)
    elif error_code in ['AccessDenied', 'UnauthorizedAccess']:
        # Check if MFA was present in session
        session_context = user_identity.get('sessionContext', {})
        session_attrs = session_context.get('attributes', {})
        mfa_authenticated = session_attrs.get('mfaAuthenticated', 'false')
        
        if mfa_authenticated == 'true':
            incident = create_policy_mismatch_incident(
                user=username,
                source_ip=source_ip,
                denied_action=event_name,
                cloudtrail_detail=detail
            )
    
    if incident:
        store_incident(incident)
        publish_alert(incident)
        emit_metric(incident)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'mode': 'detector',
                'incident_id': incident['incident_id'],
                'scenario': incident['scenario'],
                'status': 'created',
                'source': 'cloudtrail'
            })
        }
    else:
        print(f"[INFO] Event did not match any incident pattern: {event_name}")
        return {
            'statusCode': 200,
            'body': json.dumps({
                'mode': 'detector',
                'status': 'no_match',
                'event_name': event_name
            })
        }


def process_simulator_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process synthetic test events (manual CLI invoke).
    Original simulator functionality for testing and demos.
    """
    scenario = event.get('scenario', 'mfa_auth_failure')
    user = event.get('user', 'test-user')
    source_ip = event.get('source_ip', '192.0.2.1')  # TEST-NET-1 per RFC 5737
    metadata = event.get('metadata', {})
    
    print(f"[INFO] Simulator mode: generating {scenario} incident")
    
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
            'mode': 'simulator',
            'incident_id': incident['incident_id'],
            'scenario': scenario,
            'status': 'created',
            'timestamp': incident['timestamp']
        })
    }


def create_mfa_auth_failure_incident(user: str, source_ip: str, cloudtrail_detail: Dict) -> Dict[str, Any]:
    """Create incident from real CloudTrail ConsoleLogin failure."""
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
        'detection_source': 'cloudtrail',
        'detection_signal': {
            'event_name': 'ConsoleLogin',
            'event_source': 'signin.amazonaws.com',
            'error_message': cloudtrail_detail.get('errorMessage', 'Failed authentication'),
            'event_time': cloudtrail_detail.get('eventTime', ''),
            'aws_region': cloudtrail_detail.get('awsRegion', ''),
            'additional_event_data': cloudtrail_detail.get('additionalEventData', {})
        },
        'description': f'MFA authentication failure for user {user} consistent with token expiration or timing issue',
        'recommended_action': 'User must re-authenticate with valid MFA token',
        'auto_remediation': False,
        'environment': ENVIRONMENT,
        'ttl': int(time.time()) + (7 * 24 * 60 * 60)
    }


def create_policy_mismatch_incident(user: str, source_ip: str, denied_action: str, cloudtrail_detail: Dict) -> Dict[str, Any]:
    """Create incident from real CloudTrail AccessDenied event."""
    incident_id = f"POLICY-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()
    
    return {
        'incident_id': incident_id,
        'scenario': 'policy_mismatch',
        'severity': 'MEDIUM',
        'status': 'OPEN',
        'timestamp': timestamp,
        'created_at': int(time.time()),
        'user': user,
        'source_ip': source_ip,
        'detection_source': 'cloudtrail',
        'detection_signal': {
            'event_name': denied_action,
            'event_source': cloudtrail_detail.get('eventSource', ''),
            'error_code': cloudtrail_detail.get('errorCode', 'AccessDenied'),
            'error_message': cloudtrail_detail.get('errorMessage', ''),
            'event_time': cloudtrail_detail.get('eventTime', ''),
            'request_parameters': cloudtrail_detail.get('requestParameters', {})
        },
        'description': f'Policy mismatch: User {user} has MFA session but {denied_action} denied due to condition mismatch',
        'recommended_action': 'Admin must review IAM policy conditions for aws:MultiFactorAuthPresent',
        'auto_remediation': False,
        'environment': ENVIRONMENT,
        'ttl': int(time.time()) + (7 * 24 * 60 * 60)
    }


def simulate_mfa_auth_failure(user: str, source_ip: str, metadata: Dict) -> Dict[str, Any]:
    """Simulate MFA authentication failure for testing."""
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
        'detection_source': 'simulator',
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
        'ttl': int(time.time()) + (7 * 24 * 60 * 60)
    }


def simulate_rate_limiting(user: str, source_ip: str, metadata: Dict) -> Dict[str, Any]:
    """Simulate rate limiting scenario for testing."""
    incident_id = f"RATE-LIMIT-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()
    
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
        'detection_source': 'simulator',
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
        'cooldown_seconds': 300,
        'metadata': metadata,
        'environment': ENVIRONMENT,
        'ttl': int(time.time()) + (7 * 24 * 60 * 60)
    }


def simulate_policy_mismatch(user: str, source_ip: str, metadata: Dict) -> Dict[str, Any]:
    """Simulate policy mismatch scenario for testing."""
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
        'detection_source': 'simulator',
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
            'detection_source': incident.get('detection_source', 'unknown'),
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
                        {'Name': 'Environment', 'Value': ENVIRONMENT},
                        {'Name': 'Source', 'Value': incident.get('detection_source', 'unknown')}
                    ],
                    'Value': 1,
                    'Unit': 'Count'
                }
            ]
        )
        print(f"[INFO] Emitted metric for incident {incident['incident_id']}")
    except Exception as e:
        print(f"[ERROR] Failed to emit metric: {str(e)}")
