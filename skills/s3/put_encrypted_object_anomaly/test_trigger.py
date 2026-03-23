import json
from detection import run

# Simulate an attacker using their own KMS key to encrypt your data
malicious_event = {
    "_source": {
        "@timestamp": "2025-03-24T03:22:00.000Z",
        "source": {"address": "185.220.101.45", "ip": "185.220.101.45"},
        "aws": {
            "cloudtrail": {
                "user_identity": {
                    "type": "IAMUser",
                    "arn": "arn:aws:iam::851725491209:user/dev-temp-01"
                },
                "recipient_account_id": "851725491209",
                "flattened": {
                    "request_parameters": {
                        "bucketName": "company-prod-data",
                        "key": "backups/db_full_20250324.sql.enc",
                        "x-amz-server-side-encryption": "aws:kms",
                        "x-amz-server-side-encryption-aws-kms-key-id":
                            "arn:aws:kms:us-east-1:999999999999:key/attacker-key"
                    }
                }
            }
        },
        "event": {
            "action": "PutObject",
            "original": "{\"eventName\":\"PutObject\",\"userIdentity\":{\"type\":\"IAMUser\",\"userName\":\"dev-temp-01\"},\"sourceIPAddress\":\"185.220.101.45\",\"requestParameters\":{\"bucketName\":\"company-prod-data\",\"key\":\"backups/db_full_20250324.sql.enc\",\"x-amz-server-side-encryption\":\"aws:kms\",\"x-amz-server-side-encryption-aws-kms-key-id\":\"arn:aws:kms:us-east-1:999999999999:key/attacker-key\"},\"recipientAccountId\":\"851725491209\"}"
        },
        "user": {"name": "dev-temp-01"},
        "user_agent": {"original": "aws-cli/2.15.0 Windows/10"}
    }
}

run(malicious_event)