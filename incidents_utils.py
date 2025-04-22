import boto3
import uuid
from decimal import Decimal
from datetime import datetime

dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

table = dynamodb.Table('SecurityEvents')
SNS_TOPIC_ARN = 'arn:aws:sns:eu-west-1:054037129949:SecurityAlerts'

def log_event_to_dynamodb(event_type, severity, description):
    try:
        table.put_item(Item={
            'eventId': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(),
            'eventType': event_type,
            'severity': Decimal(str(severity)),
            'description': description
        })
        print("Logged to DynamoDB")
    except Exception as e:
        print(f"Error logging to DynamoDB: {e}")

def send_email_alert(event_type, severity, description):
    message = (
        f"Security Alert\n"
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
        print("Email Alert Sent:", response['MessageId'])
    except Exception as e:
        print(f"Failed to send email alert: {e}")
