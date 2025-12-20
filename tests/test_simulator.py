"""
Unit Tests for MFA Incident Simulator Handler

What we ARE testing:
- CloudTrail event classification logic
- MFA failure detection (failed login + successful login without MFA)
- Policy mismatch detection (AccessDenied with MFA session)
- Simulator mode scenario generation
- Return value structure

What we are NOT testing:
- AWS service availability
- DynamoDB write operations
- SNS notification delivery
- Real CloudTrail event flow

The signal: "Given a CloudTrail event, does my logic correctly classify it?"
"""

import json
import sys
import os
import pytest
from unittest.mock import patch, MagicMock
import importlib.util


# =============================================================================
# Dynamic Import Setup
# =============================================================================
# Handle 'lambda' being a reserved keyword in Python by loading dynamically

def load_handler_module():
    """Dynamically load handler from lambda directory (reserved keyword workaround)."""
    possible_paths = [
        os.path.join(os.path.dirname(__file__), '..', 'src', 'simulator', 'handler.py'),
        os.path.join(os.path.dirname(__file__), '..', 'lambda', 'simulator', 'handler.py'),
    ]
    
    for handler_path in possible_paths:
        handler_path = os.path.abspath(handler_path)
        if os.path.exists(handler_path):
            spec = importlib.util.spec_from_file_location("simulator_handler", handler_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules["simulator_handler"] = module
            spec.loader.exec_module(module)
            return module
    
    raise FileNotFoundError(f"Handler not found in: {possible_paths}")


# Load module at import time
handler = load_handler_module()


# =============================================================================
# Test Classes
# =============================================================================

class TestEventClassification:
    """Test the core event classification logic."""
    
    def test_is_cloudtrail_event_with_valid_event(self):
        """Verify CloudTrail event detection."""
        event = {
            "detail-type": "AWS Console Sign In via CloudTrail",
            "detail": {"eventName": "ConsoleLogin"}
        }
        
        assert handler.is_cloudtrail_event(event) is True
    
    def test_is_cloudtrail_event_with_simulator_event(self):
        """Simulator events should not be classified as CloudTrail."""
        event = {
            "scenario": "mfa_auth_failure",
            "user": "test-user"
        }
        
        assert handler.is_cloudtrail_event(event) is False
    
    def test_is_cloudtrail_event_with_empty_detail(self):
        """Events with non-dict detail should not match."""
        event = {
            "detail-type": "Something",
            "detail": "not a dict"
        }
        
        assert handler.is_cloudtrail_event(event) is False


class TestMFAFailureDetection:
    """
    Test MFA failure detection from CloudTrail ConsoleLogin events.
    
    Two failure modes:
    1. authentication_failed: Login attempt failed, MFA not used
    2. mfa_not_enforced: Login succeeded WITHOUT MFA (policy gap)
    """
    
    def test_detects_successful_login_without_mfa(
        self, 
        cloudtrail_console_login_success_no_mfa
    ):
        """
        CRITICAL TEST: Successful login without MFA should trigger incident.
        
        Scenario:
        - User: finance-analyst-01
        - IP: 203.0.113.42
        - Result: ConsoleLogin = Success
        - MFAUsed: No
        
        Expected:
        - Incident created with scenario='mfa_auth_failure'
        - failure_type='mfa_not_enforced'
        - severity='HIGH' (more severe than failed login)
        """
        with patch.object(handler, 'store_incident') as mock_store, \
             patch.object(handler, 'publish_alert'), \
             patch.object(handler, 'emit_metric'):
            
            response = handler.lambda_handler(cloudtrail_console_login_success_no_mfa, None)
            
            # Verify response structure
            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            
            assert body['mode'] == 'detector'
            assert body['status'] == 'created'
            assert body['scenario'] == 'mfa_auth_failure'
            assert body['source'] == 'cloudtrail'
            assert 'incident_id' in body
            assert body['incident_id'].startswith('MFA-AUTH-')
            
            # Verify incident was stored
            mock_store.assert_called_once()
            stored_incident = mock_store.call_args[0][0]
            
            assert stored_incident['user'] == 'finance-analyst-01'
            assert stored_incident['source_ip'] == '203.0.113.42'
            assert stored_incident['failure_type'] == 'mfa_not_enforced'
            assert stored_incident['severity'] == 'HIGH'
            assert stored_incident['detection_source'] == 'cloudtrail'
    
    def test_detects_failed_login_without_mfa(
        self, 
        cloudtrail_console_login_failed_no_mfa
    ):
        """
        Test: Failed login attempt without MFA should trigger incident.
        
        Scenario:
        - User: dev-engineer-02
        - IP: 203.0.113.42
        - Result: ConsoleLogin = Failure
        - errorMessage: "Failed authentication"
        - MFAUsed: No
        
        Expected:
        - Incident created with failure_type='authentication_failed'
        - severity='MEDIUM'
        """
        with patch.object(handler, 'store_incident') as mock_store, \
             patch.object(handler, 'publish_alert'), \
             patch.object(handler, 'emit_metric'):
            
            response = handler.lambda_handler(cloudtrail_console_login_failed_no_mfa, None)
            
            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            
            assert body['status'] == 'created'
            assert body['scenario'] == 'mfa_auth_failure'
            
            # Verify incident details
            stored_incident = mock_store.call_args[0][0]
            assert stored_incident['user'] == 'dev-engineer-02'
            assert stored_incident['failure_type'] == 'authentication_failed'
            assert stored_incident['severity'] == 'MEDIUM'
    
    def test_ignores_successful_login_with_mfa(
        self, 
        cloudtrail_console_login_success_with_mfa
    ):
        """
        Test: Successful login WITH MFA should NOT trigger incident.
        
        This is expected behavior - no action needed.
        """
        with patch.object(handler, 'store_incident') as mock_store, \
             patch.object(handler, 'publish_alert') as mock_alert, \
             patch.object(handler, 'emit_metric'):
            
            response = handler.lambda_handler(cloudtrail_console_login_success_with_mfa, None)
            
            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            
            assert body['status'] == 'no_match'
            assert body['event_name'] == 'ConsoleLogin'
            
            # Verify NO incident was stored
            mock_store.assert_not_called()
            mock_alert.assert_not_called()


class TestPolicyMismatchDetection:
    """
    Test policy mismatch detection from CloudTrail AccessDenied events.
    
    Pattern: User has active MFA session but action is denied.
    This indicates a policy condition mismatch (StringEquals vs Bool, etc.)
    """
    
    def test_detects_access_denied_with_mfa_session(
        self, 
        cloudtrail_access_denied_with_mfa
    ):
        """
        Test: AccessDenied with mfaAuthenticated=true triggers policy_mismatch.
        
        Scenario:
        - User: finance-analyst-01
        - Action: s3:GetObject
        - mfaAuthenticated: true
        - Result: AccessDenied
        
        This is the "user did everything right but policy is misconfigured" case.
        """
        with patch.object(handler, 'store_incident') as mock_store, \
             patch.object(handler, 'publish_alert'), \
             patch.object(handler, 'emit_metric'):
            
            response = handler.lambda_handler(cloudtrail_access_denied_with_mfa, None)
            
            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            
            assert body['status'] == 'created'
            assert body['scenario'] == 'policy_mismatch'
            
            # Verify incident details
            stored_incident = mock_store.call_args[0][0]
            assert stored_incident['user'] == 'finance-analyst-01'
            assert stored_incident['scenario'] == 'policy_mismatch'
            assert stored_incident['severity'] == 'MEDIUM'
            assert 'GetObject' in stored_incident['description']
    
    def test_ignores_access_denied_without_mfa_session(
        self, 
        cloudtrail_access_denied_without_mfa
    ):
        """
        Test: AccessDenied WITHOUT MFA session should NOT trigger policy_mismatch.
        
        This is expected behavior - user didn't have MFA, so denial is correct.
        """
        with patch.object(handler, 'store_incident') as mock_store, \
             patch.object(handler, 'publish_alert'), \
             patch.object(handler, 'emit_metric'):
            
            response = handler.lambda_handler(cloudtrail_access_denied_without_mfa, None)
            
            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            
            # Should not match - not a policy mismatch, just expected denial
            assert body['status'] == 'no_match'
            mock_store.assert_not_called()


class TestSimulatorMode:
    """Test simulator mode for generating synthetic incidents."""
    
    def test_simulator_mfa_auth_failure(self):
        """Test simulator generates mfa_auth_failure incidents."""
        with patch.object(handler, 'store_incident') as mock_store, \
             patch.object(handler, 'publish_alert'), \
             patch.object(handler, 'emit_metric'):
            
            event = {
                "scenario": "mfa_auth_failure",
                "user": "test-user-01",
                "source_ip": "192.0.2.100"
            }
            
            response = handler.lambda_handler(event, None)
            
            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            
            assert body['mode'] == 'simulator'
            assert body['scenario'] == 'mfa_auth_failure'
            assert body['status'] == 'created'
            
            # Verify incident structure
            stored_incident = mock_store.call_args[0][0]
            assert stored_incident['user'] == 'test-user-01'
            assert stored_incident['source_ip'] == '192.0.2.100'
            assert stored_incident['detection_source'] == 'simulator'
    
    def test_simulator_rate_limiting(self):
        """Test simulator generates rate_limiting incidents with correct metadata."""
        with patch.object(handler, 'store_incident') as mock_store, \
             patch.object(handler, 'publish_alert'), \
             patch.object(handler, 'emit_metric'):
            
            event = {
                "scenario": "rate_limiting",
                "user": "rate-limit-user",
                "metadata": {
                    "failure_count": 7,
                    "window_seconds": 45
                }
            }
            
            response = handler.lambda_handler(event, None)
            
            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            
            assert body['scenario'] == 'rate_limiting'
            
            stored_incident = mock_store.call_args[0][0]
            assert stored_incident['severity'] == 'HIGH'
            assert stored_incident['auto_remediation'] is True
            assert stored_incident['cooldown_seconds'] == 300
            assert stored_incident['detection_signal']['failure_count'] == 7
            assert stored_incident['detection_signal']['window_seconds'] == 45
    
    def test_simulator_policy_mismatch(self):
        """Test simulator generates policy_mismatch incidents."""
        with patch.object(handler, 'store_incident') as mock_store, \
             patch.object(handler, 'publish_alert'), \
             patch.object(handler, 'emit_metric'):
            
            event = {
                "scenario": "policy_mismatch",
                "user": "policy-test-user",
                "metadata": {
                    "denied_action": "dynamodb:PutItem",
                    "resource": "arn:aws:dynamodb:us-east-1:123456789012:table/secrets"
                }
            }
            
            response = handler.lambda_handler(event, None)
            
            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            
            assert body['scenario'] == 'policy_mismatch'
            
            stored_incident = mock_store.call_args[0][0]
            assert stored_incident['detection_signal']['attempted_action'] == 'dynamodb:PutItem'
            assert 'secrets' in stored_incident['detection_signal']['resource']
    
    def test_simulator_unknown_scenario_returns_error(self):
        """Test that unknown scenarios return 400 error."""
        event = {
            "scenario": "unknown_scenario",
            "user": "test-user"
        }
        
        response = handler.lambda_handler(event, None)
        
        assert response['statusCode'] == 400
        body = json.loads(response['body'])
        assert 'error' in body
        assert 'valid_scenarios' in body


class TestIncidentStructure:
    """Verify incident objects have required fields for downstream processing."""
    
    def test_incident_has_required_fields(self):
        """All incidents must have these fields for DynamoDB and alerting."""
        with patch.object(handler, 'store_incident') as mock_store, \
             patch.object(handler, 'publish_alert'), \
             patch.object(handler, 'emit_metric'):
            
            event = {
                "scenario": "mfa_auth_failure",
                "user": "field-test-user"
            }
            
            handler.lambda_handler(event, None)
            
            incident = mock_store.call_args[0][0]
            
            # Required fields for DynamoDB
            assert 'incident_id' in incident
            assert 'scenario' in incident
            assert 'severity' in incident
            assert 'status' in incident
            assert 'timestamp' in incident
            assert 'created_at' in incident
            assert 'user' in incident
            assert 'ttl' in incident  # For DynamoDB TTL
            
            # Required fields for alerting
            assert 'description' in incident
            assert 'recommended_action' in incident
            assert 'detection_source' in incident
            
            # Required for CloudWatch metrics
            assert 'environment' in incident
    
    def test_incident_id_format(self):
        """Incident IDs should follow expected format for each scenario."""
        scenarios = [
            ('mfa_auth_failure', 'MFA-AUTH-'),
            ('rate_limiting', 'RATE-LIMIT-'),
            ('policy_mismatch', 'POLICY-')
        ]
        
        for scenario, prefix in scenarios:
            with patch.object(handler, 'store_incident') as mock_store, \
                 patch.object(handler, 'publish_alert'), \
                 patch.object(handler, 'emit_metric'):
                
                event = {"scenario": scenario, "user": "test"}
                handler.lambda_handler(event, None)
                
                incident = mock_store.call_args[0][0]
                assert incident['incident_id'].startswith(prefix), \
                    f"Expected {scenario} incident_id to start with {prefix}"


class TestBurstDetection:
    """
    Test detection of burst patterns (multiple failures in short window).
    
    Note: Rate limiting detection in production uses CloudWatch Insights
    for post-hoc analysis. These tests verify the handler can process
    individual events that would contribute to a burst pattern.
    """
    
    def test_each_failure_in_burst_creates_incident(
        self, 
        cloudtrail_burst_5_failures_60s
    ):
        """
        Each failed login in a burst should create an individual incident.
        
        Burst aggregation happens at the CloudWatch Insights level,
        not in the Lambda handler. The handler creates incidents for
        each event, which are then correlated in post-hoc analysis.
        """
        with patch.object(handler, 'store_incident') as mock_store, \
             patch.object(handler, 'publish_alert'), \
             patch.object(handler, 'emit_metric'):
            
            incidents_created = 0
            
            for event in cloudtrail_burst_5_failures_60s:
                response = handler.lambda_handler(event, None)
                body = json.loads(response['body'])
                
                if body.get('status') == 'created':
                    incidents_created += 1
            
            # All 5 failures should create incidents
            assert incidents_created == 5
            assert mock_store.call_count == 5


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_handles_missing_username(self):
        """Handler should gracefully handle events with missing userName."""
        with patch.object(handler, 'store_incident') as mock_store, \
             patch.object(handler, 'publish_alert'), \
             patch.object(handler, 'emit_metric'):
            
            event = {
                "detail-type": "AWS Console Sign In via CloudTrail",
                "detail": {
                    "eventName": "ConsoleLogin",
                    "sourceIPAddress": "1.2.3.4",
                    "responseElements": {"ConsoleLogin": "Success"},
                    "additionalEventData": {"MFAUsed": "No"},
                    "userIdentity": {
                        "type": "IAMUser",
                        "principalId": "AIDA123456789"
                        # Note: no userName field
                    }
                }
            }
            
            response = handler.lambda_handler(event, None)
            
            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            
            # Should still create incident using principalId as fallback
            assert body['status'] == 'created'
            
            incident = mock_store.call_args[0][0]
            assert incident['user'] == 'AIDA123456789'  # Falls back to principalId
    
    def test_handles_empty_additional_event_data(self):
        """Handler should handle missing additionalEventData gracefully."""
        with patch.object(handler, 'store_incident') as mock_store, \
             patch.object(handler, 'publish_alert'), \
             patch.object(handler, 'emit_metric'):
            
            event = {
                "detail-type": "AWS Console Sign In via CloudTrail",
                "detail": {
                    "eventName": "ConsoleLogin",
                    "sourceIPAddress": "1.2.3.4",
                    "responseElements": {"ConsoleLogin": "Success"},
                    # Note: no additionalEventData
                    "userIdentity": {
                        "type": "IAMUser",
                        "userName": "test-user"
                    }
                }
            }
            
            response = handler.lambda_handler(event, None)
            
            # Should not crash, but should not match (MFAUsed defaults to 'Yes')
            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            assert body['status'] == 'no_match'
    
    def test_handles_empty_event(self):
        """Handler should handle empty events gracefully."""
        with patch.object(handler, 'store_incident'), \
             patch.object(handler, 'publish_alert'), \
             patch.object(handler, 'emit_metric'):
            
            event = {}
            
            # Should treat as simulator mode with defaults
            response = handler.lambda_handler(event, None)
            
            # Default scenario is mfa_auth_failure, so it should work
            assert response['statusCode'] in [200, 400]


class TestIntegration:
    """
    Integration-style tests using moto mocks.
    These test the full flow including AWS service interactions.
    """
    
    def test_full_flow_with_mocked_aws(self, mock_all_aws):
        """
        Test complete incident flow with mocked AWS services.
        
        This verifies:
        1. Event classification
        2. DynamoDB storage
        3. Return structure
        """
        # Note: This test uses the moto-mocked AWS services
        # The handler will actually write to the mocked DynamoDB
        
        event = {
            "scenario": "rate_limiting",
            "user": "integration-test-user",
            "source_ip": "10.0.0.1"
        }
        
        response = handler.lambda_handler(event, None)
        
        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        
        assert body['status'] == 'created'
        incident_id = body['incident_id']
        
        # Verify incident is in DynamoDB
        table = mock_all_aws['table']
        item = table.get_item(Key={'incident_id': incident_id})
        
        assert 'Item' in item
        assert item['Item']['user'] == 'integration-test-user'
        assert item['Item']['scenario'] == 'rate_limiting'

