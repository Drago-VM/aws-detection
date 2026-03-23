import json
import anthropic
import os

# ── ABOUT THIS SKILL ──────────────────────────────────────────────────
# Detects IAM GetUserPolicy calls that suggest reconnaissance —
# a common first step before privilege escalation attacks.
#
# ── WHAT GetUserPolicy DOES ───────────────────────────────────────────
# GetUserPolicy returns the inline policy attached to an IAM user.
# Attackers use this to map out what permissions users have before:
#   1. Trying to steal credentials from a more-privileged user
#   2. Creating a new policy that mimics an existing powerful one
#   3. Understanding what actions won't be logged/blocked
#
# ── ABOUT YOUR REAL LOG ───────────────────────────────────────────────
# This skill was built from a real ELK/CloudTrail log where:
#
#   Caller:       queue-inspector (IAMUser)
#   Target:       queue-inspector (reading their OWN policy)
#   Policy:       queue-inspector-role
#   Source IP:    36.255.87.4  →  Bengaluru, India (external ISP)
#   ASN:          Gatik Business Solutions (not AWS infrastructure)
#   User Agent:   aws-cli/2.15.28 Windows/10  (human on laptop)
#   Time:         2025-07-18T10:58:20Z
#
# Why this is interesting:
#   - User is running AWS CLI from a Windows laptop in India
#   - IP is external (not an AWS/internal IP)
#   - Reading own policy via CLI = checking what you're allowed to do
#   - This is LOW-MEDIUM risk: could be legitimate dev work,
#     OR could be an attacker who just got credentials and is
#     exploring what access they have
#
# ── ELK DOCUMENT STRUCTURE FOR IAM EVENTS ────────────────────────────
# IAM events differ slightly from S3 events in ELK:
#
#   _source.event.action          = "GetUserPolicy"
#   _source.user.name             = caller's username
#   _source.user.target.name      = target username (whose policy is read)
#   _source.source.ip             = IP address of caller
#   _source.source.geo.*          = GeoIP enrichment by ELK
#   _source.source.as.organization.name = ASN/ISP name
#   _source.user_agent.original   = CLI/SDK string
#   _source.user_agent.os.name    = OS (Windows/Linux/Mac)
#   _source.aws.cloudtrail.flattened.request_parameters.policyName
#   _source.event.original        = raw CloudTrail JSON string
#
# ── HOW THIS DETECTION SCORES RISK ───────────────────────────────────
# Rather than a simple True/False, this skill assigns a risk score
# based on multiple signals. Each suspicious signal adds points.
# If total score >= threshold, the alert fires.
#
#   +30  External IP (not AWS/internal range)
#   +20  Human CLI tool on Windows/Mac (not automation)
#   +25  Reading a DIFFERENT user's policy (cross-user recon)
#   +20  Reading a high-privilege policy name
#   +15  Call outside business hours (UTC 22:00 - 06:00)
#   +10  Caller username matches suspicious patterns (temp/contractor)
#
# Score >= 40 = alert fires
# ─────────────────────────────────────────────────────────────────────

ALERT_THRESHOLD = 40

# AWS internal and service IP prefixes — these are trusted
TRUSTED_IP_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.",
    "54.239.", "54.242.", "52.95.", "52.46.",
)

# IAM automation typically uses these user agents — not suspicious
TRUSTED_USER_AGENTS = (
    "aws-sdk-java",
    "Boto3",
    "aws-sdk-go",
    "lambda.amazonaws.com",
    "iam.amazonaws.com",
)

# Policy names that suggest high privilege
HIGH_VALUE_POLICY_KEYWORDS = (
    "admin", "administrator", "fullaccess", "full-access",
    "poweruser", "root", "iam", "billing",
    "securityaudit", "readonly",
)

# Username patterns that suggest lower-trust identities
SUSPICIOUS_CALLER_PATTERNS = (
    "contractor", "temp", "tmp", "test",
    "external", "vendor", "intern", "readonly",
    "audit", "scanner", "bot",
)

# Business hours in UTC (adjust for your timezone)
BUSINESS_HOURS_START = 6   # 06:00 UTC
BUSINESS_HOURS_END = 22    # 22:00 UTC


# ── HELPERS ───────────────────────────────────────────────────────────

def extract_source(elk_doc):
    """Unwrap _source if present, otherwise treat doc as source directly."""
    return elk_doc.get("_source", elk_doc)


def get_raw_cloudtrail(source):
    """Parse the raw CloudTrail JSON string from event.original."""
    raw_str = source.get("event", {}).get("original", "")
    if raw_str:
        try:
            return json.loads(raw_str)
        except (json.JSONDecodeError, TypeError):
            pass
    return {}


def deep_get(obj, *keys):
    """
    Safely traverse nested dicts.
    deep_get(source, "source", "geo", "country_name") → "India"
    """
    for key in keys:
        if isinstance(obj, dict):
            obj = obj.get(key)
        else:
            return None
    return obj


def is_external_ip(ip):
    """Returns True if IP is not from a trusted internal/AWS range."""
    if not ip:
        return False
    return not any(ip.startswith(p) for p in TRUSTED_IP_PREFIXES)


def is_human_cli(user_agent):
    """
    Returns True if the user agent looks like a human running CLI,
    rather than an automated SDK/service call.
    """
    if not user_agent:
        return False
    ua_lower = user_agent.lower()
    # Trusted automation agents → not human
    if any(t.lower() in ua_lower for t in TRUSTED_USER_AGENTS):
        return False
    # AWS CLI on Windows or Mac → human
    if "aws-cli" in ua_lower and (
        "windows" in ua_lower or "mac" in ua_lower or "darwin" in ua_lower
    ):
        return True
    return False


def is_high_value_policy(policy_name):
    """Returns True if policy name suggests high privileges."""
    name_lower = policy_name.lower()
    return any(kw in name_lower for kw in HIGH_VALUE_POLICY_KEYWORDS)


def is_suspicious_caller(username):
    """Returns True if username matches low-trust patterns."""
    name_lower = username.lower()
    return any(kw in name_lower for kw in SUSPICIOUS_CALLER_PATTERNS)


def is_outside_business_hours(timestamp_str):
    """Returns True if event happened outside UTC business hours."""
    try:
        # timestamp looks like: 2025-07-18T10:58:20.000Z
        hour = int(timestamp_str[11:13])
        return hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END
    except (TypeError, IndexError, ValueError):
        return False


# ── MAIN DETECTION: RISK SCORING ─────────────────────────────────────

def score_event(elk_doc):
    """
    Returns (score, signals) where:
      score   = integer risk score
      signals = list of strings explaining what contributed to the score
    """
    source = extract_source(elk_doc)
    raw = get_raw_cloudtrail(source)

    # ── Extract all relevant fields ────────────────────────────────────

    # Event action
    action = (
        deep_get(source, "event", "action") or
        raw.get("eventName", "")
    )

    # Caller username
    caller = (
        deep_get(source, "user", "name") or
        deep_get(source, "related", "user", 0) or
        raw.get("userIdentity", {}).get("userName", "unknown")
    )

    # Target username (whose policy is being read)
    target = (
        deep_get(source, "user", "target", "name") or
        deep_get(source, "aws", "cloudtrail", "flattened",
                 "request_parameters", "userName") or
        raw.get("requestParameters", {}).get("userName", "unknown")
    )

    # Policy name being read
    policy_name = (
        deep_get(source, "aws", "cloudtrail", "flattened",
                 "request_parameters", "policyName") or
        raw.get("requestParameters", {}).get("policyName", "")
    )

    # Source IP
    source_ip = (
        deep_get(source, "source", "ip") or
        deep_get(source, "source", "address") or
        raw.get("sourceIPAddress", "")
    )

    # GeoIP enrichment (ELK adds this automatically)
    country = deep_get(source, "source", "geo", "country_name") or "unknown"
    city = deep_get(source, "source", "geo", "city_name") or "unknown"
    asn_org = deep_get(source, "source", "as", "organization", "name") or "unknown"

    # User agent
    user_agent = (
        deep_get(source, "user_agent", "original") or
        raw.get("userAgent", "")
    )

    # OS from user agent
    os_name = deep_get(source, "user_agent", "os", "name") or ""

    # Timestamp
    timestamp = source.get("@timestamp", "")

    # ── Score each signal ──────────────────────────────────────────────
    score = 0
    signals = []

    # Signal 1: external IP
    if is_external_ip(source_ip):
        score += 30
        signals.append(
            f"+30  External IP {source_ip} "
            f"({city}, {country} / ASN: {asn_org})"
        )

    # Signal 2: human CLI on Windows/Mac
    if is_human_cli(user_agent):
        score += 20
        signals.append(
            f"+20  Human CLI call on {os_name} "
            f"(not automation) — {user_agent[:60]}"
        )

    # Signal 3: reading a DIFFERENT user's policy (cross-user recon)
    if caller and target and caller != target:
        score += 25
        signals.append(
            f"+25  Cross-user recon — '{caller}' reading '{target}' policy"
        )

    # Signal 4: high-privilege policy name
    if policy_name and is_high_value_policy(policy_name):
        score += 20
        signals.append(
            f"+20  High-value policy name: '{policy_name}'"
        )

    # Signal 5: outside business hours
    if is_outside_business_hours(timestamp):
        score += 15
        signals.append(
            f"+15  Outside business hours (UTC): {timestamp}"
        )

    # Signal 6: suspicious caller pattern
    if is_suspicious_caller(caller):
        score += 10
        signals.append(
            f"+10  Suspicious caller pattern in username: '{caller}'"
        )

    return score, signals, {
        "action": action,
        "caller": caller,
        "target": target,
        "policy_name": policy_name,
        "source_ip": source_ip,
        "country": country,
        "city": city,
        "asn_org": asn_org,
        "user_agent": user_agent,
        "os_name": os_name,
        "timestamp": timestamp,
    }


def detect(elk_doc):
    """
    Returns (triggered, score, signals, fields).
    triggered = True if risk score meets threshold.
    """
    source = extract_source(elk_doc)
    raw = get_raw_cloudtrail(source)

    action = (
        deep_get(source, "event", "action") or
        raw.get("eventName", "")
    )

    if action != "GetUserPolicy":
        return False, 0, [f"Not a GetUserPolicy event (got: {action})"], {}

    score, signals, fields = score_event(elk_doc)
    triggered = score >= ALERT_THRESHOLD
    return triggered, score, signals, fields


# ── CLAUDE ENRICHMENT ─────────────────────────────────────────────────

def enrich_with_claude(elk_doc, score, signals, fields):
    """
    Sends the suspicious event + risk score breakdown to Claude
    for a plain English analyst report.
    """
    source = extract_source(elk_doc)
    raw = get_raw_cloudtrail(source)

    prompt_file = os.path.join(os.path.dirname(__file__), "prompt.txt")
    with open(prompt_file) as f:
        template = f.read()

    context = {
        "risk_score": score,
        "alert_threshold": ALERT_THRESHOLD,
        "risk_signals": signals,
        "parsed_fields": fields,
        "raw_cloudtrail_event": raw,
        "elk_geo_enrichment": {
            "country": fields.get("country"),
            "city": fields.get("city"),
            "asn_org": fields.get("asn_org"),
            "source_ip": fields.get("source_ip"),
        }
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
    triggered, score, signals, fields = detect(elk_doc)

    caller = fields.get("caller", "unknown")
    target = fields.get("target", "unknown")
    policy = fields.get("policy_name", "unknown")
    ip = fields.get("source_ip", "unknown")
    country = fields.get("country", "unknown")

    print(f"Checking GetUserPolicy")
    print(f"  Caller:  {caller}")
    print(f"  Target:  {target}")
    print(f"  Policy:  {policy}")
    print(f"  IP:      {ip} ({country})")
    print(f"  Score:   {score} / threshold {ALERT_THRESHOLD}")
    print()

    if signals:
        print("Risk signals detected:")
        for s in signals:
            print(f"  {s}")
        print()

    if triggered:
        print(f"[!] ALERT FIRED — Risk score {score} exceeds threshold {ALERT_THRESHOLD}")
        print("    Sending to Claude for analysis...\n")
        analysis = enrich_with_claude(elk_doc, score, signals, fields)
        print("=" * 60)
        print(analysis)
        print("=" * 60)
    else:
        print(f"[OK] No alert — score {score} below threshold {ALERT_THRESHOLD}\n")


if __name__ == "__main__":
    sample_file = os.path.join(os.path.dirname(__file__), "sample_event.json")
    with open(sample_file) as f:
        elk_doc = json.load(f)
    run(elk_doc)
