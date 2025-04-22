import boto3
from datetime import datetime, timezone, timedelta
from incidents_utils import log_event_to_dynamodb, send_email_alert
from classify_threat_with_comprehend import analyze_sentiment
from lambda_block_ip import block_ip_in_waf

guardduty_client = boto3.client('guardduty')
iam_client = boto3.client('iam')

def get_detector_id():
    detectors = guardduty_client.list_detectors()
    if not detectors['DetectorIds']:
        print("No GuardDuty detectors found.")
        return None
    return detectors['DetectorIds'][0]

# removes console login and disables all access keys
def disable_iam_user(username):
    print(f"Disabling IAM user: {username}")
    try:
        iam_client.delete_login_profile(UserName=username)
        print(f"Console access disabled for {username}")
    except iam_client.exceptions.NoSuchEntityException:
        print(f"No console login found for {username}")

    try:
        keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
        for key in keys:
            iam_client.update_access_key(
                UserName=username,
                AccessKeyId=key['AccessKeyId'],
                Status='Inactive'
            )
            print(f"Access key {key['AccessKeyId']} disabled")
    except Exception as e:
        print(f"Failed to disable access keys: {e}")



def extract_ip(finding):
    try:
        return finding['Service']['Action']['RemoteIpDetails']['IpAddressV4']
    except KeyError:
        try:
            return finding['Resource']['InstanceDetails']['NetworkInterfaces'][0]['PublicIp']
        except (KeyError, IndexError):
            return None

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
        username = f.get('Resource', {}).get('AccessKeyDetails', {}).get('UserName')

        print(f"\nThreat Detected")
        print(f"Type: {event_type}\nSeverity: {severity}\nDescription: {description}")

        sentiment = analyze_sentiment(description)
        print(f"Sentiment: {sentiment}")

        log_event_to_dynamodb(event_type, severity, description)
        send_email_alert(event_type, severity, description)

        if severity >= 5.0 and sentiment in ['NEGATIVE', 'MIXED'] and ip_address:
            block_ip_in_waf(ip_address)

        if event_type.startswith('IAMUser/') and severity >= 7.0 and username:
            disable_iam_user(username)

if __name__ == "__main__":
    detector_id = get_detector_id()
    if detector_id:
        process_threats(detector_id)