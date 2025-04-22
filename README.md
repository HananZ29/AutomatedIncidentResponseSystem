# ☁️ Cloud-Based Automated Incident Response System

## 📌 Project Description

This project is a **cloud-native, serverless security automation system** built on AWS. It automatically detects, analyzes, and mitigates cybersecurity threats in real time using:

- **AWS CloudTrail** and **GuardDuty** for threat detection  
- **AWS Lambda** for automated incident response  
- **AWS WAF** to block malicious IPs  
- **Amazon Comprehend** for log analysis  
- **DynamoDB** for event logging  
- **SNS** for real-time alerts  
- **IAM & KMS** for access control and compliance

---

## 🛠️ AWS Setup & Execution

---

### 🔹 1. Enable GuardDuty

- Go to [GuardDuty Console](https://console.aws.amazon.com/guardduty)
- Select your region (e.g., `eu-west-1`)
- Click **"Enable GuardDuty"**

---

### 🔹 2. IAM Permissions

Ensure your IAM user has the following policies attached:

- `AmazonGuardDutyFullAccess`
- `AWSWAF_FullAccess`
- `CloudWatchLogsFullAccess`
- `ComprehendReadOnlyAccess`

---

### 🔹 3. Configure AWS CLI

```bash
aws configure
```

---

### 🔸 Monitor GuardDuty Findings

```bash
pip install boto3
python monitor_guardduty.py
```

---

### 🔸 Set Up the Lambda Function

####  Step 1: Create a WAF IP Set

1. Go to **WAF → IP sets → Create IP set**
2. Name: `BlockedIPs`
3. Scope: `Regional`
4. Leave IPs empty (Lambda will update them)
5. Click **Create**

---

####  Step 2: Create and Upload Lambda Function

1. Go to **Lambda → Create function**
2. Select:
   - Author from scratch
   - Name: `lambda_block_ip`
   - Runtime: `Python 3.10`
3. After creation, go to **Code → Upload from → .zip file**
4. Upload `lambda_block_ip.zip`
5. Set **Handler** to:

   ```
   lambda_block_ip.lambda_handler
   ```

6. In the code, update:

   ```python
   WAF_IPSET_ID = "your_ipset_id"
   ```

7. Click **Deploy**

---

####  Step 3: Attach Permissions to Lambda

Go to:  
**Lambda → Configuration → Permissions → Execution Role**

Attach these policies:
- `AWSWAF_FullAccess`
- `AmazonGuardDutyReadOnlyAccess`
- `CloudWatchLogsFullAccess`

---

####  Step 4: Create an EventBridge Rule

1. Go to **EventBridge → Create Rule**
2. Name: `guardduty-to-lambda`
3. Rule type: **Event pattern**
4. Event source:
   - AWS service: `GuardDuty`
   - Event type: `GuardDuty Finding`
5. Target: `lambda_block_ip` Lambda function
6. Allow EventBridge to invoke the Lambda
7. Click **Create Rule**

---

### 🔸 Analyze Logs with AWS Comprehend

```bash
python classify_threat_with_comprehend.py
```

---

## 🧠 System Architecture

```text
CloudTrail → GuardDuty → Lambda → WAF
     ↘︎                      ↘︎
     Comprehend         DynamoDB → SNS
```

---

