import boto3
import uuid
from decimal import Decimal
from datetime import datetime, timezone, timedelta


guardduty_client = boto3.client('guardduty')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')
table = dynamodb.Table('SecurityEvents')
SNS_TOPIC_ARN = 'arn:aws:sns:eu-west-1:490004629030:SecurityAlerts'


def get_detector_id():
    detectors = guardduty_client.list_detectors()
    if not detectors['DetectorIds']:
        print("No GuardDuty detectors found.")
        return None
    return detectors['DetectorIds'][0]


def log_event_to_dynamodb(event_type, severity, description):
    try:
        table.put_item(Item={
            'eventId': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(),
            'eventType': event_type,
            'severity': Decimal(str(severity)),
            'description': description
        })
        print("✅ Logged to DynamoDB")
    except Exception as e:
        print(f"❌ Error logging to DynamoDB: {e}")

def send_email_alert(event_type, severity, description):
    message = (
        f"🚨 Security Alert 🚨\n"
        f"Type: {event_type}\n"
        f"Severity: {severity}\n"
        f"{description}"
    )
    try:
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject="Security Threat Detected"
        )
        print("📧 Email Alert Sent:", response['MessageId'])
    except Exception as e:
        print(f"❌ Failed to send email alert: {e}")


def fetch_recent_findings(detector_id):
    time_threshold = int((datetime.now(timezone.utc) - timedelta(hours=24)).timestamp())

    finding_ids = guardduty_client.list_findings(
        DetectorId=detector_id,
        FindingCriteria={
            'Criterion': {
                'updatedAt': {'Gte': time_threshold}
            }
        },
        MaxResults=10
    )['FindingIds']

    if not finding_ids:
        print("No recent threats detected.")
        return

    findings = guardduty_client.get_findings(
        DetectorId=detector_id,
        FindingIds=finding_ids
    )['Findings']

    for f in findings:
        print(f"\n🔍 Finding ID: {f['Id']}")
        print(f"Type: {f['Type']}")
        print(f"First Seen: {f['Service']['EventFirstSeen']}")
        print(f"Severity: {f['Severity']}")
        print(f"Description: {f['Description']}")
        print(f"Resource: {f['Resource']}")
        print("-" * 50)

        log_event_to_dynamodb(
            event_type=f['Type'],
            severity=f['Severity'],
            description=f['Description']
        )

        send_email_alert(
            event_type=f['Type'],
            severity=f['Severity'],
            description=f['Description']
        )

if __name__ == "__main__":
    detector_id = get_detector_id()
    if detector_id:
        fetch_recent_findings(detector_id)
