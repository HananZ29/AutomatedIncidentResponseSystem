# Cloud-Based Automated Incident Response System

## 📌 Project Description

This project is a **cloud-native, serverless security automation system** built on AWS. It automatically detects, analyzes, and mitigates cybersecurity threats in real time.

The system leverages:
- **AWS CloudTrail** and **GuardDuty** for threat detection
- **AWS Lambda** for automated response
- **AWS WAF** to block malicious IPs
- **AWS Comprehend** for log analysis
- **Amazon DynamoDB** for event logging
- **Amazon SNS** for real-time alerts
- **IAM & KMS** for access control and security compliance

----

### AWS Setup
1. **Enable GuardDuty**
   - Go to [GuardDuty Console](https://console.aws.amazon.com/guardduty)
   - Select your region (e.g., `us-east-1`)
   - Click **"Enable GuardDuty"**

2. **IAM Permissions**
   Ensure your IAM user has the following managed policies:
   - `AmazonGuardDutyFullAccess`
   - `ComprehendReadOnly`

3. **Configure AWS CLI**
   Run:
   ```bash
   aws configure
**To run the code**
Run: pip install pip install boto3
# 1. Get recent GuardDuty findings
python monitor_guardduty.py

# 2. Analyze the log with AWS Comprehend
python classify_threat_with_comprehend.py
**System Architecture**
CloudTrail → GuardDuty → Lambda → WAF
     ↘︎                      ↘︎
     Comprehend         DynamoDB → SNS


