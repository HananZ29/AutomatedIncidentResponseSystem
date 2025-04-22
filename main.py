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

    # Threat type mapping
    type_mapping = {
        "UnauthorizedAccess": "Unauthorized Access",
        "Recon": "Reconnaissance Activity",
        "Trojan": "Malware Communication",
        "Backdoor": "Remote Access Tool",
        "Persistence": "Persistence Mechanism",
        "PrivilegeEscalation": "Privilege Escalation",
        "CredentialAccess": "Credential Access Attempt",
        "Discovery": "Resource Discovery",
        "Exfiltration": "Data Exfiltration",
        "CommandAndControl": "C2 Communication",
        "Impact": "System Impact",
    }

    for finding in findings:
        finding_id = finding["Id"]
        finding_type_raw = finding["Type"]
        threat_category = type_mapping.get(finding_type_raw.split(":")[0], "Unknown Threat")
        description = finding["Description"]
        sentiment = analyze_sentiment(description)
        ip_address = extract_ip(finding)
        severity = finding.get("Severity", 0)

        log_event_to_dynamodb(finding_type_raw, severity, description)

        send_email_alert(finding_type_raw, severity, description)


        print(f"\nFinding ID: {finding_id}")
        print(f"Description: {description}")
        print(f"Sentiment: {sentiment}")
        print(f"Threat Type: {threat_category}")
        print(f"Severity: {severity}")
        print(f"IP Blocked: {ip_address if ip_address else 'N/A'}")

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
