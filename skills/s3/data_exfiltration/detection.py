import json
import anthropic
import os

LARGE_DOWNLOAD_BYTES = 50 * 1024 * 1024

TRUSTED_IP_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.",
    "54.239.", "54.242.", "52.95.", "52.46.",   # AWS internal service IPs
)

TRUSTED_USER_AGENTS = (
    "aws-sdk-go",
    "aws-sdk-java",
    "aws-sdk-python",
    "Boto3",
    "s3.amazonaws.com",
    "lambda.amazonaws.com",
    "elasticmapreduce",
)

SENSITIVE_BUCKETS = (
    "financial", "payroll", "confidential", "backup",
    "audit", "credentials", "secrets", "prod-data",
    "customer", "pii", "hr-", "legal"
)

def extract_source(elk_doc):
    """
    Handles both formats:
      - Full ELK document with _source wrapper
      - Just the _source content directly
    """
    if "_source" in elk_doc:
        return elk_doc["_source"]
    return elk_doc


def get_raw_cloudtrail(source):
    """
    Parses the raw CloudTrail event from event.original (a JSON string).
    Falls back to an empty dict if not present.
    """
    raw_str = source.get("event", {}).get("original", "")
    if raw_str:
        try:
            return json.loads(raw_str)
        except json.JSONDecodeError:
            pass
    return {}


def get_field(source, *paths):
    """
    Safely walks a nested dict using dot-separated path keys.
    Tries each path in order, returns first non-None value found.
    Example: get_field(source, "aws.cloudtrail.flattened.additional_eventdata.bytesTransferredOut")
    """
    for path in paths:
        obj = source
        for key in path.split("."):
            if isinstance(obj, dict):
                obj = obj.get(key)
            else:
                obj = None
                break
        if obj is not None:
            return obj
    return None


def is_trusted_ip(ip):
    """Returns True if IP belongs to a trusted internal or AWS service range."""
    return any(ip.startswith(p) for p in TRUSTED_IP_PREFIXES)


def is_trusted_agent(user_agent):
    """Returns True if the user agent looks like an internal AWS SDK/service."""
    ua_lower = user_agent.lower()
    return any(svc.lower() in ua_lower for svc in TRUSTED_USER_AGENTS)


def is_sensitive_bucket(bucket_name):
    """Returns True if bucket name contains a sensitive keyword."""
    name_lower = bucket_name.lower()
    return any(kw in name_lower for kw in SENSITIVE_BUCKETS)



def detect(elk_doc):
    """
    Returns (True, reason) if this ELK CloudTrail document looks like
    data exfiltration. Returns (False, reason) if it looks normal.
    """
    source = extract_source(elk_doc)
    raw = get_raw_cloudtrail(source)


    action = (
        get_field(source, "event.action") or
        raw.get("eventName", "")
    )

    # Source IP
    source_ip = (
        get_field(source, "source.ip") or
        get_field(source, "source.address") or
        raw.get("sourceIPAddress", "")
    )

    # Bytes transferred out
    bytes_out = (
        get_field(source, "aws.cloudtrail.flattened.additional_eventdata.bytesTransferredOut") or
        raw.get("additionalEventData", {}).get("bytesTransferredOut", 0) or
        0
    )

    # Bucket name
    bucket = (
        get_field(source, "aws.cloudtrail.flattened.request_parameters.bucketName") or
        raw.get("requestParameters", {}).get("bucketName", "")
    )

    # IAM username
    username = (
        get_field(source, "user.name") or
        raw.get("userIdentity", {}).get("userName", "unknown")
    )

    # User agent
    user_agent = (
        get_field(source, "user_agent.original") or
        raw.get("userAgent", "")
    )

    if action != "GetObject":
        return False, f"Not a GetObject event (got: {action})"

    if is_trusted_ip(source_ip) and is_trusted_agent(user_agent):
        return False, (
            f"Trusted source — IP {source_ip} is an AWS internal IP "
            f"and user agent matches known SDK ({user_agent[:40]})"
        )

    # ── External IP + sensitive bucket 
    if not is_trusted_ip(source_ip) and is_sensitive_bucket(bucket):
        return True, (
            f"External IP {source_ip} accessed sensitive bucket '{bucket}' "
            f"— possible targeted exfiltration"
        )

    # ── External IP + large download 
    if not is_trusted_ip(source_ip) and bytes_out > LARGE_DOWNLOAD_BYTES:
        mb = bytes_out / (1024 * 1024)
        return True, (
            f"External IP {source_ip} downloaded {mb:.1f}MB from "
            f"bucket '{bucket}' — exceeds {LARGE_DOWNLOAD_BYTES // (1024*1024)}MB threshold"
        )

    return False, (
        f"No alert — {bytes_out} bytes from IP {source_ip} "
        f"by user '{username}' on bucket '{bucket}'"
    )


# ── CLAUDE ENRICHMENT 

def enrich_with_claude(elk_doc):
    """
    Sends the suspicious ELK document to Claude for plain English analysis.
    Passes both the ELK metadata AND the raw CloudTrail event for full context.
    """
    source = extract_source(elk_doc)
    raw = get_raw_cloudtrail(source)

    prompt_file = os.path.join(os.path.dirname(__file__), "prompt.txt")
    with open(prompt_file) as f:
        template = f.read()

    context = {
        "elk_metadata": {
            "source_ip": get_field(source, "source.ip"),
            "username": get_field(source, "user.name"),
            "timestamp": source.get("@timestamp"),
            "bytes_transferred_out": get_field(
                source,
                "aws.cloudtrail.flattened.additional_eventdata.bytesTransferredOut"
            ),
            "bucket": get_field(
                source,
                "aws.cloudtrail.flattened.request_parameters.bucketName"
            ),
            "file_key": get_field(
                source,
                "aws.cloudtrail.flattened.request_parameters.key"
            ),
            "geo_country": get_field(source, "source.geo.country_name"),
            "geo_city": get_field(source, "source.geo.city_name"),
            "asn_org": get_field(source, "source.as.organization.name"),
            "user_agent": get_field(source, "user_agent.original"),
        },
        "raw_cloudtrail_event": raw
    }

    prompt = template.replace("{event}", json.dumps(context, indent=2))

    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.content[0].text


def run(elk_doc):
    source = extract_source(elk_doc)
    username = get_field(source, "user.name") or "unknown"
    bucket = get_field(
        source,
        "aws.cloudtrail.flattened.request_parameters.bucketName"
    ) or "unknown"
    ip = get_field(source, "source.ip") or "unknown"

    print(f"Checking GetObject | user={username} | bucket={bucket} | ip={ip}")

    triggered, reason = detect(elk_doc)

    if triggered:
        print(f"\n[!] ALERT FIRED — {reason}")
        print("    Sending to Claude for analysis...\n")
        analysis = enrich_with_claude(elk_doc)
        print("=" * 60)
        print(analysis)
        print("=" * 60)
    else:
        print(f"[OK] No alert — {reason}\n")


if __name__ == "__main__":
    sample_file = os.path.join(os.path.dirname(__file__), "sample_event.json")
    with open(sample_file) as f:
        elk_doc = json.load(f)
    run(elk_doc)
