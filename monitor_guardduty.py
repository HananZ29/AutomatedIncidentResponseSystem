import boto3
from datetime import datetime, timezone, timedelta

# Step 1: Connect to GuardDuty
client = boto3.client('guardduty')

# Step 2: Get the Detector ID
def get_detector_id():
    detectors = client.list_detectors()
    if not detectors['DetectorIds']:
        print("No GuardDuty detectors found.")
        return None
    return detectors['DetectorIds'][0]

# Step 3: Fetch recent findings (last 24h)
def fetch_recent_findings(detector_id):
    # Use UNIX timestamp instead of ISO format
    time_threshold = int((datetime.now(timezone.utc) - timedelta(hours=24)).timestamp())

    finding_ids = client.list_findings(
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

    findings = client.get_findings(
        DetectorId=detector_id,
        FindingIds=finding_ids
    )['Findings']

    for f in findings:
        print(f"\n Finding ID: {f['Id']}")
        print(f"Type: {f['Type']}")
        print(f"First Seen: {f['Service']['EventFirstSeen']}")
        print(f"Severity: {f['Severity']}")
        print(f"Description: {f['Description']}")
        print(f"Resource: {f['Resource']}")
        print("-" * 50)

if __name__ == "__main__":
    detector_id = get_detector_id()
    if detector_id:
        fetch_recent_findings(detector_id)
