import json
import anthropic
import os

# ── RAW LOG EXAMPLE ───────────────────────────────────────────────────
# GenerateDataKey is a KMS API call that creates an encryption key.
# Legitimate use: services like S3, RDS call this automatically
#                 when they need to encrypt your data at rest.
#
# Suspicious use: an attacker who has compromised an IAM user can call
#                 GenerateDataKey themselves, use it to encrypt files,
#                 then exfiltrate the encrypted data. They hold the key.
#
# Red flags:
#   - Called by a user account (not a service like s3.amazonaws.com)
#   - Called from an external IP (not an AWS service IP)
#   - Caller is an ETL/pipeline service account (unusual for direct KMS calls)
#   - Time is outside business hours
#
# Legitimate caller userAgent:  "s3.amazonaws.com" or "lambda.amazonaws.com"
# Suspicious caller userAgent:  "aws-cli/2.0" or "python-requests/2.28"
# ─────────────────────────────────────────────────────────────────────

TRUSTED_SERVICE_AGENTS = [
    "s3.amazonaws.com",
    "lambda.amazonaws.com",
    "rds.amazonaws.com",
    "ec2.amazonaws.com",
    "elasticmapreduce.amazonaws.com"
]

SUSPICIOUS_CALLER_PATTERNS = [
    "contractor", "temp", "tmp", "etl",
    "pipeline", "test", "external"
]


def is_human_caller(event):
    """Returns True if this looks like a human/script call rather than an AWS service."""
    user_agent = event.get("userAgent", "")
    return not any(svc in user_agent for svc in TRUSTED_SERVICE_AGENTS)


def is_suspicious_user(event):
    username = event.get("userIdentity", {}).get("userName", "").lower()
    return any(kw in username for kw in SUSPICIOUS_CALLER_PATTERNS)


def is_external_ip(ip):
    trusted = ("10.", "172.16.", "192.168.", "52.95.")
    return not any(ip.startswith(p) for p in trusted)


def detect(event):
    """
    Fires when a human user (not an AWS service) calls GenerateDataKey
    from an external IP — a potential sign of attacker-controlled encryption.
    """
    if event.get("eventName") != "GenerateDataKey":
        return False

    source_ip = event.get("sourceIPAddress", "")

    if is_human_caller(event) and is_external_ip(source_ip):
        return True

    if is_suspicious_user(event):
        return True

    return False


def enrich_with_claude(event):
    prompt_file = os.path.join(os.path.dirname(__file__), "prompt.txt")
    with open(prompt_file) as f:
        template = f.read()

    prompt = template.replace("{event}", json.dumps(event, indent=2))
    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.content[0].text


def run(event):
    caller = event.get("userIdentity", {}).get("userName", "unknown")
    key_id = event.get("requestParameters", {}).get("keyId", "unknown")
    print(f"Checking GenerateDataKey by {caller} using key: {key_id}")

    if detect(event):
        print("\n[!] ALERT FIRED — Anomalous KMS data key generation")
        print("    Sending to Claude for analysis...\n")
        analysis = enrich_with_claude(event)
        print("=" * 50)
        print(analysis)
        print("=" * 50)
    else:
        print("[OK] No alert — looks like a normal service call\n")


if __name__ == "__main__":
    sample_file = os.path.join(os.path.dirname(__file__), "sample_event.json")
    with open(sample_file) as f:
        sample_event = json.load(f)
    run(sample_event)