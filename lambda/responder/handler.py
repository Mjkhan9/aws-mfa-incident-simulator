"""
MFA Incident Responder

Assisted remediation for rate limiting scenarios.
Updates incident state after cooldown - does NOT modify IAM directly.

This is constrained auto-response:
- Only handles rate_limiting scenarios
- Only updates incident state in DynamoDB
- Logs all actions for audit trail
- Sends SNS notification on resolution
"""

import json
import boto3
import time
from datetime import datetime, timezone
from typing import Dict, Any

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')
cloudwatch = boto3.client('cloudwatch')

# Environment variables
import os
TABLE_NAME = os.environ.get('INCIDENTS_TABLE', 'mfa-incidents')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Process incidents eligible for assisted remediation.
    
    Triggered by:
    - EventBridge scheduled rule (every 5 minutes)
    - Direct invocation for testing
    
    Only processes rate_limiting incidents that have exceeded cooldown.
    """
    print(f"[INFO] Responder triggered at {datetime.now(timezone.utc).isoformat()}")
    
    # Get incidents eligible for remediation
    eligible_incidents = get_eligible_incidents()
    
    if not eligible_incidents:
        print("[INFO] No incidents eligible for remediation")
        return {
            'statusCode': 200,
            'body': json.dumps({'processed': 0, 'message': 'No eligible incidents'})
        }
    
    processed = 0
    for incident in eligible_incidents:
        try:
            process_remediation(incident)
            processed += 1
        except Exception as e:
            print(f"[ERROR] Failed to process {incident['incident_id']}: {str(e)}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'processed': processed,
            'total_eligible': len(eligible_incidents)
        })
    }


def get_eligible_incidents() -> list:
    """
    Query DynamoDB for rate_limiting incidents past cooldown period.
    
    Eligibility criteria:
    - scenario = 'rate_limiting'
    - status = 'OPEN'
    - created_at + cooldown_seconds < current_time
    """
    try:
        table = dynamodb.Table(TABLE_NAME)
        current_time = int(time.time())
        
        # Scan for open rate_limiting incidents
        # In production, use a GSI for efficiency
        response = table.scan(
            FilterExpression='scenario = :scenario AND #status = :status',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':scenario': 'rate_limiting',
                ':status': 'OPEN'
            }
        )
        
        eligible = []
        for item in response.get('Items', []):
            created_at = item.get('created_at', 0)
            cooldown = item.get('cooldown_seconds', 300)
            
            if current_time > (created_at + cooldown):
                eligible.append(item)
                print(f"[INFO] Incident {item['incident_id']} eligible for remediation")
        
        return eligible
        
    except Exception as e:
        print(f"[ERROR] Failed to query incidents: {str(e)}")
        return []


def process_remediation(incident: Dict[str, Any]) -> None:
    """
    Process assisted remediation for a single incident.
    
    Actions:
    1. Update incident status to RESOLVED
    2. Record resolution timestamp
    3. Calculate resolution time (simulated MTTR)
    4. Send SNS notification
    5. Emit CloudWatch metric
    
    Does NOT:
    - Modify IAM users or policies
    - Unlock accounts
    - Make any destructive changes
    """
    incident_id = incident['incident_id']
    print(f"[INFO] Processing remediation for {incident_id}")
    
    # Calculate resolution time
    created_at = incident.get('created_at', int(time.time()))
    resolved_at = int(time.time())
    resolution_time_seconds = resolved_at - created_at
    
    # Update incident in DynamoDB
    update_incident_status(
        incident_id=incident_id,
        new_status='RESOLVED',
        resolution_time=resolution_time_seconds,
        resolution_notes='Cooldown period completed. Rate limiting cleared. User may attempt re-authentication.'
    )
    
    # Send resolution notification
    send_resolution_notification(incident, resolution_time_seconds)
    
    # Emit resolution metric
    emit_resolution_metric(incident, resolution_time_seconds)
    
    print(f"[INFO] Remediation complete for {incident_id} (resolution time: {resolution_time_seconds}s)")


def update_incident_status(
    incident_id: str,
    new_status: str,
    resolution_time: int,
    resolution_notes: str
) -> None:
    """Update incident status in DynamoDB."""
    try:
        table = dynamodb.Table(TABLE_NAME)
        
        table.update_item(
            Key={'incident_id': incident_id},
            UpdateExpression='''
                SET #status = :status,
                    resolved_at = :resolved_at,
                    resolution_time_seconds = :resolution_time,
                    resolution_notes = :notes,
                    remediation_type = :remediation_type
            ''',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':status': new_status,
                ':resolved_at': datetime.now(timezone.utc).isoformat(),
                ':resolution_time': resolution_time,
                ':notes': resolution_notes,
                ':remediation_type': 'assisted_auto'
            }
        )
        
        print(f"[INFO] Updated incident {incident_id} to {new_status}")
        
    except Exception as e:
        print(f"[ERROR] Failed to update incident: {str(e)}")
        raise


def send_resolution_notification(incident: Dict[str, Any], resolution_time: int) -> None:
    """Send SNS notification for resolved incident."""
    if not SNS_TOPIC_ARN:
        print("[WARN] SNS_TOPIC_ARN not configured, skipping notification")
        return
    
    try:
        message = {
            'event': 'INCIDENT_RESOLVED',
            'incident_id': incident['incident_id'],
            'scenario': incident['scenario'],
            'user': incident['user'],
            'original_severity': incident['severity'],
            'resolution_time_seconds': resolution_time,
            'resolution_time_formatted': format_duration(resolution_time),
            'remediation_type': 'assisted',
            'notes': 'Cooldown period completed. Rate limiting cleared.',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[RESOLVED] MFA Incident: {incident['incident_id']}",
            Message=json.dumps(message, indent=2)
        )
        
        print(f"[INFO] Sent resolution notification for {incident['incident_id']}")
        
    except Exception as e:
        print(f"[ERROR] Failed to send notification: {str(e)}")


def emit_resolution_metric(incident: Dict[str, Any], resolution_time: int) -> None:
    """Emit CloudWatch metrics for resolution."""
    try:
        cloudwatch.put_metric_data(
            Namespace='MFAIncidentSimulator',
            MetricData=[
                {
                    'MetricName': 'IncidentResolved',
                    'Dimensions': [
                        {'Name': 'Scenario', 'Value': incident['scenario']},
                        {'Name': 'Environment', 'Value': ENVIRONMENT}
                    ],
                    'Value': 1,
                    'Unit': 'Count'
                },
                {
                    'MetricName': 'ResolutionTimeSeconds',
                    'Dimensions': [
                        {'Name': 'Scenario', 'Value': incident['scenario']},
                        {'Name': 'Environment', 'Value': ENVIRONMENT}
                    ],
                    'Value': resolution_time,
                    'Unit': 'Seconds'
                }
            ]
        )
        
        print(f"[INFO] Emitted resolution metrics for {incident['incident_id']}")
        
    except Exception as e:
        print(f"[ERROR] Failed to emit metrics: {str(e)}")


def format_duration(seconds: int) -> str:
    """Format seconds as human-readable duration."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        secs = seconds % 60
        return f"{minutes}m {secs}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"


# For local testing
if __name__ == '__main__':
    print("Testing responder logic...")
    
    # Mock incident for testing
    test_incident = {
        'incident_id': 'RATE-LIMIT-TEST123',
        'scenario': 'rate_limiting',
        'severity': 'HIGH',
        'status': 'OPEN',
        'user': 'test-user',
        'created_at': int(time.time()) - 400,  # 400 seconds ago
        'cooldown_seconds': 300
    }
    
    print(f"Test incident: {json.dumps(test_incident, indent=2)}")
    print(f"Would be eligible: {int(time.time()) > (test_incident['created_at'] + test_incident['cooldown_seconds'])}")

