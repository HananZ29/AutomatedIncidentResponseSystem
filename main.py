import boto3
from datetime import datetime, timezone, timedelta
from incidents_utils import log_event_to_dynamodb, send_email_alert
from classify_threat_with_comprehend import analyze_sentiment  
from lambda_block_ip import block_ip_in_waf

guardduty_client = boto3.client('guardduty')


def get_detector_id():
    detectors = guardduty_client.list_detectors()
    if not detectors['DetectorIds']:
        print("No GuardDuty detectors found.")
        return None
    return detectors['DetectorIds'][0]


def process_threats(detector_id):
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
        event_type = f['Type']
        severity = f['Severity']
        description = f['Description']
        ip_address = extract_ip(f)

        print(f"\nThreat Detected")
        print(f"Type: {event_type}\nSeverity: {severity}\nDescription: {description}")

        # Step 1: Analyze text with Comprehend
        sentiment = analyze_sentiment(description)
        print(f"Sentiment: {sentiment}")

        log_event_to_dynamodb(event_type, severity, description)

        send_email_alert(event_type, severity, description)

        if severity >= 5.0 and sentiment in ['NEGATIVE', 'MIXED']:
            if ip_address:
                block_ip_in_waf(ip_address)
            else:
                print("No IP address found to block.")


def extract_ip(finding):
    try:
        return finding['Service']['Action']['RemoteIpDetails']['IpAddressV4']
    except KeyError:
        try:
            return finding['Resource']['InstanceDetails']['NetworkInterfaces'][0]['PublicIp']
        except (KeyError, IndexError):
            return None


if __name__ == "__main__":
    detector_id = get_detector_id()
    if detector_id:
        process_threats(detector_id)
