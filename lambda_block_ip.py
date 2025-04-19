import json
import boto3

# created this ipset from aws waf, the ip addreses are currently empty bas when there's actually an attack it'll add them to this list
WAF_IPSET_ID = '94efc72b-5cb7-48b3-aa5d-143d75de413c'
WAF_SCOPE = 'REGIONAL'  # or 'CLOUDFRONT'
WAF_NAME = 'BlockedIPs'

# Initialize WAF client
waf = boto3.client('wafv2')
def lambda_handler(event, context):
    print("Event received:", json.dumps(event, indent=2))

    ip = None
    try:
        ip = event['detail']['service']['action']['remoteIpDetails']['ipAddressV4']
    except KeyError:
        # Fallback for sample findings with different structure
        try:
            ip = event['detail']['resource']['instanceDetails']['networkInterfaces'][0]['publicIp']
        except KeyError:
            print("No IP address found in the event.")
            return {"statusCode": 400, "body": "No IP address found"}

    print(f"Blocked IP: {ip}")
    block_ip_in_waf(ip)

    return {"statusCode": 200, "body": f"IP {ip} blocked in WAF"}

#
# def lambda_handler(event, context):
#     print("Event received:", json.dumps(event, indent=2))
#
#     # Try to get the malicious IP address from the GuardDuty finding
#     try:
#         ip = event['detail']['service']['action']['remoteIpDetails']['ipAddressV4']
#     except KeyError:
#         print("No IP address found in the event.")
#         return {"statusCode": 400, "body": "No IP address found"}
#
#     # Block the IP in AWS WAF
#     block_ip_in_waf(ip)
#
#     return {"statusCode": 200, "body": f"IP {ip} blocked in WAF"}
#

def block_ip_in_waf(ip):
    # Get current IPSet info
    ipset = waf.get_ip_set(Name=WAF_NAME, Scope=WAF_SCOPE, Id=WAF_IPSET_ID)
    addresses = ipset['IPSet']['Addresses']
    lock_token = ipset['LockToken']
    cidr_ip = f"{ip}/32"

    if cidr_ip not in addresses:
        addresses.append(cidr_ip)
        waf.update_ip_set(
            Name=WAF_NAME,
            Scope=WAF_SCOPE,
            Id=WAF_IPSET_ID,
            Addresses=addresses,
            LockToken=lock_token
        )
        print(f"Blocked IP: {ip}")
    else:
        print(f"IP {ip} already blocked")
