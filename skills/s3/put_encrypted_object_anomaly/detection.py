import json
import base64
import anthropic
import os

# ── ABOUT THIS SKILL ──────────────────────────────────────────────────
# Detects anomalous S3 PutObject calls where the encryption configuration
# suggests ransomware staging, data theft prep, or privilege abuse.
#
# ── WHAT THIS REAL LOG SHOWS ─────────────────────────────────────────
# Your sample_event.json is a 100% LEGITIMATE event:
#
#   Caller:     cloudtrail.amazonaws.com  (AWSService type — not human)
#   File:       AWSLogs/.../CloudTrail/...json.gz  (CloudTrail writing its own logs)
#   KMS key:    arn:aws:kms:us-east-1:851725491209:...  (same account = trusted)
#   ACL:        bucket-owner-full-control  (standard CloudTrail ACL)
#   Bytes in:   2108  (tiny 2KB log file)
#   Context:    base64 decodes to CloudTrail ARN  (proves legitimacy)
#
# The detection should correctly print [OK] for this event.
#
# ── WHAT A MALICIOUS PutObject LOOKS LIKE ────────────────────────────
# The same event becomes suspicious when:
#
#   Caller:     IAMUser or AssumedRole  (human or script, not AWSService)
#   KMS key:    belongs to a DIFFERENT account  (attacker controls the key)
#   ACL:        anything other than bucket-owner-full-control
#   File ext:   .enc / .locked / .crypto / .ransom
#   Context:    missing, empty, or doesn't reference your own resources
#   Source IP:  real external IP (not a service name like cloudtrail.amazonaws.com)
#
# ── HOW KMS ENCRYPTION CONTEXT WORKS ─────────────────────────────────
# The x-amz-server-side-encryption-context is base64-encoded JSON.
# CloudTrail always sets it to its own ARN, e.g.:
#   {"aws:cloudtrail:arn":"arn:aws:cloudtrail:us-east-1:851725491209:trail/..."}
#
# An attacker using their own KMS key would have either:
#   - No context at all
#   - A context referencing a foreign account ARN
#   - A context that doesn't match any known AWS service pattern
#
# ── ELK FIELD STRUCTURE FOR PutObject EVENTS ─────────────────────────
# Unlike IAM events, S3 PutObject events in ELK may NOT have:
#   - source.ip  (when caller is AWSService, sourceIPAddress is a hostname)
#   - source.geo  (no GeoIP for service callers)
#   - user.name  (no user for AWSService type)
#
# Instead look at:
#   aws.cloudtrail.user_identity.type       = "AWSService" or "IAMUser"
#   aws.cloudtrail.user_identity.invoked_by = "cloudtrail.amazonaws.com"
#   aws.cloudtrail.flattened.request_parameters.*  = encryption details
#   source.address  = either IP or service hostname
# ─────────────────────────────────────────────────────────────────────

# Your AWS account ID — KMS keys from other accounts are suspicious
OWN_ACCOUNT_ID = "851725491209"  # update if needed

# AWS services that legitimately write encrypted objects to S3
TRUSTED_AWS_SERVICES = (
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "s3.amazonaws.com",
    "lambda.amazonaws.com",
    "elasticmapreduce.amazonaws.com",
    "delivery.logs.amazonaws.com",
)

# Legitimate S3 key path prefixes written by AWS services
TRUSTED_KEY_PREFIXES = (
    "AWSLogs/",
    "aws-controltower/",
    "Config/",
    "CloudTrail/",
)

# File extensions that suggest attacker-controlled encryption
RANSOMWARE_EXTENSIONS = (
    ".enc", ".locked", ".crypto", ".crypt",
    ".ransom", ".encrypted", ".crypted",
)

# Standard encryption types — unexpected values are suspicious
KNOWN_ENCRYPTION_TYPES = ("aws:kms", "AES256", "aws:kms:dsse")


# ── HELPERS ───────────────────────────────────────────────────────────

def extract_source(elk_doc):
    return elk_doc.get("_source", elk_doc)


def get_raw_cloudtrail(source):
    raw_str = source.get("event", {}).get("original", "")
    if raw_str:
        try:
            return json.loads(raw_str)
        except (json.JSONDecodeError, TypeError):
            pass
    return {}


def deep_get(obj, *keys):
    for key in keys:
        if isinstance(obj, dict):
            obj = obj.get(key)
        else:
            return None
    return obj


def decode_kms_context(context_b64):
    """
    Decodes the base64 KMS encryption context to readable JSON.
    Returns dict if decodable, empty dict if not.

    Example:
      Input:  "eyJhd3M6Y2xvdWR0cmFpbDphcm4iOi4uLn0="
      Output: {"aws:cloudtrail:arn": "arn:aws:cloudtrail:..."}
    """
    if not context_b64:
        return {}
    try:
        decoded = base64.b64decode(context_b64).decode("utf-8")
        return json.loads(decoded)
    except Exception:
        return {}


def extract_kms_account_id(kms_key_arn):
    """
    Extracts account ID from KMS ARN.
    arn:aws:kms:us-east-1:851725491209:key/abc → "851725491209"
    """
    if not kms_key_arn:
        return None
    parts = kms_key_arn.split(":")
    if len(parts) >= 5:
        return parts[4]
    return None


def is_aws_service_caller(source):
    """
    Returns True if the caller is an AWS service (not a human/IAM user).
    AWSService type callers are pre-authorized AWS internal services.
    """
    identity_type = deep_get(
        source, "aws", "cloudtrail", "user_identity", "type"
    )
    if identity_type == "AWSService":
        return True

    # Also check raw event
    raw = get_raw_cloudtrail(source)
    return raw.get("userIdentity", {}).get("type") == "AWSService"


def get_invoked_by(source):
    """Returns the invokedBy field — which AWS service made the call."""
    invoked = deep_get(
        source, "aws", "cloudtrail", "user_identity", "invoked_by"
    )
    if invoked:
        return invoked
    raw = get_raw_cloudtrail(source)
    return raw.get("userIdentity", {}).get("invokedBy", "")


def is_trusted_service_caller(source):
    """
    Returns True if the call came from a known trusted AWS service
    writing to expected paths (e.g. CloudTrail writing its own logs).
    """
    if not is_aws_service_caller(source):
        return False

    invoked_by = get_invoked_by(source)
    if invoked_by not in TRUSTED_AWS_SERVICES:
        return False

    # Extra check: is the file path a known AWS-service path?
    key = deep_get(
        source, "aws", "cloudtrail", "flattened", "request_parameters", "key"
    ) or ""
    return any(key.startswith(prefix) for prefix in TRUSTED_KEY_PREFIXES)


# ── MAIN DETECTION ────────────────────────────────────────────────────

def detect(elk_doc):
    """
    Returns (triggered, reason, details) for a PutObject ELK event.

    Fires when:
      1. KMS key belongs to a foreign account (attacker controls decryption)
      2. File has a ransomware-like extension
      3. Encryption context is missing or references foreign resources
      4. Unknown/unexpected encryption type is used
      5. Human/IAM caller (not AWSService) using KMS on sensitive bucket
    """
    source = extract_source(elk_doc)
    raw = get_raw_cloudtrail(source)

    # Must be PutObject
    action = (
        deep_get(source, "event", "action") or
        raw.get("eventName", "")
    )
    if action != "PutObject":
        return False, f"Not a PutObject event (got: {action})", {}

    # Extract key fields
    req_params = (
        deep_get(source, "aws", "cloudtrail", "flattened", "request_parameters")
        or raw.get("requestParameters", {})
        or {}
    )

    kms_key_arn = (
        req_params.get("x-amz-server-side-encryption-aws-kms-key-id") or
        deep_get(source, "aws", "cloudtrail", "flattened",
                 "response_elements", "x-amz-server-side-encryption-aws-kms-key-id") or
        ""
    )

    encryption_type = (
        req_params.get("x-amz-server-side-encryption") or
        raw.get("additionalEventData", {}).get("SSEApplied") or
        ""
    )

    context_b64 = req_params.get("x-amz-server-side-encryption-context", "")
    kms_context = decode_kms_context(context_b64)

    bucket = req_params.get("bucketName", "")
    file_key = req_params.get("key", "")

    caller_type = (
        deep_get(source, "aws", "cloudtrail", "user_identity", "type") or
        raw.get("userIdentity", {}).get("type", "")
    )
    invoked_by = get_invoked_by(source)
    caller_name = (
        deep_get(source, "user", "name") or
        raw.get("userIdentity", {}).get("userName", "") or
        invoked_by or
        "unknown"
    )

    recipient_account = (
        deep_get(source, "aws", "cloudtrail", "recipient_account_id") or
        raw.get("recipientAccountId", OWN_ACCOUNT_ID)
    )

    kms_account = extract_kms_account_id(kms_key_arn)

    details = {
        "action": action,
        "bucket": bucket,
        "file_key": file_key,
        "caller_type": caller_type,
        "caller_name": caller_name,
        "invoked_by": invoked_by,
        "kms_key_arn": kms_key_arn,
        "kms_key_account": kms_account,
        "own_account": recipient_account,
        "encryption_type": encryption_type,
        "kms_context_decoded": kms_context,
        "timestamp": source.get("@timestamp", ""),
    }

    # ── CHECK 1: Trusted AWS service writing to known path → safe ─────
    if is_trusted_service_caller(source):
        return False, (
            f"Trusted AWS service write — invokedBy={invoked_by}, "
            f"key path starts with known prefix, "
            f"KMS key belongs to account {kms_account}"
        ), details

    # ── CHECK 2: KMS key from a foreign account → high risk ───────────
    if kms_key_arn and kms_account and kms_account != recipient_account:
        return True, (
            f"FOREIGN KMS KEY — key account {kms_account} does not match "
            f"recipient account {recipient_account}. "
            f"Attacker may control the decryption key: {kms_key_arn}"
        ), details

    # ── CHECK 3: Ransomware file extension ────────────────────────────
    if any(file_key.lower().endswith(ext) for ext in RANSOMWARE_EXTENSIONS):
        return True, (
            f"RANSOMWARE EXTENSION — file '{file_key}' has a suspicious "
            f"extension suggesting attacker-controlled encryption"
        ), details

    # ── CHECK 4: Encryption context references a foreign account ──────
    if kms_context:
        context_str = json.dumps(kms_context)
        # If context contains an ARN, check it references own account
        if "arn:aws" in context_str and recipient_account not in context_str:
            return True, (
                f"SUSPICIOUS KMS CONTEXT — encryption context references "
                f"resources outside account {recipient_account}: {kms_context}"
            ), details

    # ── CHECK 5: Unknown encryption type ──────────────────────────────
    if encryption_type and encryption_type not in KNOWN_ENCRYPTION_TYPES:
        return True, (
            f"UNKNOWN ENCRYPTION TYPE — '{encryption_type}' is not a "
            f"recognised AWS SSE type. Possible misconfiguration or evasion."
        ), details

    # ── CHECK 6: Human/IAM caller using KMS (lower risk, still note) ──
    if caller_type == "IAMUser" and kms_key_arn:
        return True, (
            f"HUMAN KMS UPLOAD — IAM user '{caller_name}' directly uploaded "
            f"with KMS encryption (unusual — normally done by services). "
            f"Verify this is expected behaviour."
        ), details

    return False, (
        f"No alert — {caller_type} write to {bucket}/{file_key[:40]} "
        f"using {encryption_type} with own-account KMS key"
    ), details


# ── CLAUDE ENRICHMENT ─────────────────────────────────────────────────

def enrich_with_claude(reason, details, raw):
    prompt_file = os.path.join(os.path.dirname(__file__), "prompt.txt")
    with open(prompt_file) as f:
        template = f.read()

    context = {
        "alert_reason": reason,
        "parsed_fields": details,
        "kms_context_explanation": (
            "The x-amz-server-side-encryption-context is base64-encoded JSON. "
            "Decoded value is shown in parsed_fields.kms_context_decoded. "
            "Legitimate CloudTrail writes always include their own trail ARN here."
        ),
        "raw_cloudtrail_event": raw,
    }

    prompt = template.replace("{event}", json.dumps(context, indent=2))

    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.content[0].text


# ── RUN ───────────────────────────────────────────────────────────────

def run(elk_doc):
    source = extract_source(elk_doc)
    raw = get_raw_cloudtrail(source)

    req_params = (
        deep_get(source, "aws", "cloudtrail", "flattened", "request_parameters")
        or {}
    )
    bucket = req_params.get("bucketName", "unknown")
    file_key = req_params.get("key", "unknown")
    caller_type = deep_get(
        source, "aws", "cloudtrail", "user_identity", "type"
    ) or "unknown"
    invoked_by = get_invoked_by(source) or "n/a"
    enc_type = req_params.get("x-amz-server-side-encryption", "none")

    print(f"Checking PutObject")
    print(f"  Caller:      {caller_type} / invokedBy={invoked_by}")
    print(f"  Bucket:      {bucket}")
    print(f"  File:        {file_key[:70]}")
    print(f"  Encryption:  {enc_type}")
    print()

    triggered, reason, details = detect(elk_doc)

    if triggered:
        print(f"[!] ALERT FIRED")
        print(f"    Reason: {reason}\n")
        print("    Sending to Claude for analysis...\n")
        analysis = enrich_with_claude(reason, details, raw)
        print("=" * 60)
        print(analysis)
        print("=" * 60)
    else:
        print(f"[OK] No alert — {reason}\n")

        # Helpful explanation of why this specific log is safe
        kms_context_b64 = req_params.get(
            "x-amz-server-side-encryption-context", ""
        )
        if kms_context_b64:
            decoded = decode_kms_context(kms_context_b64)
            if decoded:
                print(f"[INFO] KMS context decoded: {json.dumps(decoded, indent=2)}")


if __name__ == "__main__":
    import json
    import os

    sample_file = os.path.join(os.path.dirname(__file__), "sample_event.json")
    with open(sample_file) as f:
        elk_doc = json.load(f)

    run(elk_doc)