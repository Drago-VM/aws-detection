import json
import hashlib
import anthropic
import os
from datetime import datetime, timezone

# ── ABOUT THIS SKILL ──────────────────────────────────────────────────
# This skill is fundamentally different from all others in this repo.
#
# Every other skill watches for suspicious EVENTS (who did what, when).
# This skill watches for anomalies in CloudTrail's INTEGRITY SYSTEM —
# the digest chain that proves logs have not been tampered with.
#
# ── WHAT CLOUDTRAIL DIGEST FILES ARE ─────────────────────────────────
# Every hour, CloudTrail writes a digest file to S3 at:
#   AWSLogs/{account}/CloudTrail-Digest/{region}/{trail}.json.gz
#
# Each digest file contains:
#   - The time window it covers (1 hour)
#   - SHA-256 hashes of every log file from that hour
#   - A hash of the PREVIOUS digest (creating a chain)
#   - An RSA signature over everything (using AWS's private key)
#
# This creates a tamper-evident HASH CHAIN:
#   Digest[hour 1] → Digest[hour 2] → Digest[hour 3] → ...
#                    ↑ contains hash of previous
#
# If an attacker deletes or modifies any log file, the hash chain breaks.
# If they try to forge a digest, the RSA signature fails.
#
# ── WHAT YOUR REAL LOG REVEALS ───────────────────────────────────────
# Your sample is a digest file from 2025-07-16 13:34 UTC.
# The critical finding:
#
#   newestEventTime: null
#   oldestEventTime: null
#   logFiles:        []
#
# This means ZERO CloudTrail events were captured in this 1-hour window
# (12:34 to 13:34 UTC). The digest file exists (the chain continues),
# but it contains NO log files.
#
# This is suspicious but has two possible explanations:
#   1. LEGITIMATE: the trail is inactive or this region is quiet
#   2. SUSPICIOUS: an attacker ran StopLogging during this window,
#      performed their actions (invisible), then restarted logging —
#      leaving a gap in the audit trail
#
# Your skill detects BOTH the empty gap AND other digest anomalies.
#
# ── ELK DIGEST DOCUMENT STRUCTURE ────────────────────────────────────
# Digest files have a completely different ELK structure from events:
#
#   NO event.action, NO userIdentity, NO sourceIPAddress
#   NO aws.cloudtrail.user_identity.*
#   NO source.ip, NO user.name
#
# Instead, look at:
#   aws.cloudtrail.digest.start_time      = window start
#   aws.cloudtrail.digest.end_time        = window end
#   aws.cloudtrail.digest.log_files       = list of log hashes (may be [])
#   aws.cloudtrail.digest.signature_algorithm = how it was signed
#   aws.cloudtrail.digest.s3_bucket       = where digest lives
#   aws.cloudtrail.digest.previous_s3_bucket = where previous digest is
#   file.hash.sha256                      = ELK-computed hash of digest file
#   log.file.path                         = S3 path of this digest file
#   event.original                        = full digest JSON (parseable)
#
# The raw digest JSON (in event.original) contains additional fields:
#   digestPublicKeyFingerprint  = which AWS key signed this
#   previousDigestHashValue     = SHA-256 of previous digest file
#   previousDigestSignature     = RSA signature of previous digest
#   previousDigestHashAlgorithm = "SHA-256"
#   newestEventTime             = most recent event in window (null if empty)
#   oldestEventTime             = oldest event in window (null if empty)
#   logFiles                    = array of {s3Bucket, s3Object, hashValue, ...}
#
# ── DETECTION SIGNALS ─────────────────────────────────────────────────
# This skill checks for 5 categories of anomaly:
#
#   1. EMPTY WINDOW — logFiles=[] during business hours
#      Could mean StopLogging was used to hide activity
#
#   2. CHAIN BREAK — previousDigest fields are missing or null
#      Could mean an attacker deleted a preceding digest to break the chain
#
#   3. SIGNATURE ALGORITHM DOWNGRADE — not SHA256withRSA
#      Could mean a forged digest using a weaker algorithm
#
#   4. BUCKET MISMATCH — digest stored in a different bucket
#      Could mean an attacker redirected digest writes to hide tampering
#
#   5. EXCESSIVE GAP — window covers more or less than expected 1 hour
#      Could mean digest generation was paused and restarted
# ─────────────────────────────────────────────────────────────────────

EXPECTED_SIGNATURE_ALGORITHM = "SHA256withRSA"
EXPECTED_HASH_ALGORITHM = "SHA-256"
EXPECTED_WINDOW_MINUTES = 60       # digests cover exactly 1 hour
WINDOW_TOLERANCE_MINUTES = 5       # allow small clock drift
BUSINESS_HOURS_START = 6
BUSINESS_HOURS_END = 22


# ── HELPERS ───────────────────────────────────────────────────────────

def extract_source(elk_doc):
    return elk_doc.get("_source", elk_doc)


def get_raw_digest(source):
    """
    Parses the full digest JSON from event.original.
    This contains fields ELK doesn't index into aws.cloudtrail.digest.*
    such as newestEventTime, digestPublicKeyFingerprint, previousDigest*.
    """
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


def is_digest_document(source):
    """
    Returns True if this ELK document is a CloudTrail Digest file.
    Digest files have aws.cloudtrail.digest.* fields and no user_identity.
    """
    digest = deep_get(source, "aws", "cloudtrail", "digest")
    if not digest:
        return False
    # Regular events have user_identity — digests don't
    has_user_identity = deep_get(
        source, "aws", "cloudtrail", "user_identity", "type"
    )
    return digest is not None and not has_user_identity


def parse_timestamp(ts_str):
    """Safely parses ISO timestamp string to datetime object."""
    if not ts_str:
        return None
    try:
        ts_str = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return None


def compute_window_minutes(start_str, end_str):
    """Returns the number of minutes between start and end timestamps."""
    start = parse_timestamp(start_str)
    end = parse_timestamp(end_str)
    if start and end:
        return (end - start).total_seconds() / 60
    return None


def is_business_hours(timestamp_str):
    """Returns True if timestamp falls within UTC business hours."""
    try:
        hour = int(timestamp_str[11:13])
        return BUSINESS_HOURS_START <= hour < BUSINESS_HOURS_END
    except (TypeError, IndexError, ValueError):
        return False


def verify_file_hash(source, raw_digest):
    """
    Compares ELK's computed file.hash.sha256 against
    the previousDigestSignature in the raw digest.

    Note: file.hash.sha256 is ELK's hash of the digest FILE ITSELF.
    previousDigestSignature is the RSA SIGNATURE of the PREVIOUS digest.
    These are intentionally different — we check structural consistency,
    not cryptographic verification (that requires AWS public keys).
    """
    elk_hash = deep_get(source, "file", "hash", "sha256")
    prev_sig = raw_digest.get("previousDigestSignature", "")

    if elk_hash and prev_sig:
        # The file hash and previous signature are both in hex
        # They should be different lengths (hash=64 chars, sig=256+ chars)
        # A match would indicate something very wrong
        if elk_hash == prev_sig:
            return False, "file.hash.sha256 matches previousDigestSignature — impossible in a valid digest"
    return True, "hash structure looks normal"


# ── MAIN DETECTION: ANOMALY SCORING ──────────────────────────────────

def score_event(elk_doc):
    """
    Scores anomalies in the CloudTrail digest document.

    Scoring:
      +40  Empty log window during business hours (possible StopLogging gap)
      +20  Empty log window outside business hours (lower risk, quieter period)
      +35  Missing or null previousDigest fields (chain break)
      +30  Non-standard signature algorithm (possible forge attempt)
      +25  Digest window significantly outside expected 1-hour period
      +20  Digest bucket differs from previous digest bucket (redirect)
      +15  Hash algorithm downgrade (not SHA-256)
    """
    source = extract_source(elk_doc)
    raw = get_raw_digest(source)

    # ── Extract digest fields ──────────────────────────────────────────

    # From ELK-indexed fields
    digest = deep_get(source, "aws", "cloudtrail", "digest") or {}
    start_time = digest.get("start_time", "")
    end_time = digest.get("end_time", "")
    log_files_elk = digest.get("log_files", [])
    sig_algorithm = digest.get("signature_algorithm", "")
    s3_bucket = digest.get("s3_bucket", "")
    prev_s3_bucket = digest.get("previous_s3_bucket", "")
    prev_hash_algorithm = digest.get("previous_hash_algorithm", "")

    # From raw digest JSON (richer fields not fully indexed by ELK)
    log_files_raw = raw.get("logFiles", [])
    newest_event_time = raw.get("newestEventTime")
    oldest_event_time = raw.get("oldestEventTime")
    prev_hash_value = raw.get("previousDigestHashValue")
    prev_signature = raw.get("previousDigestSignature")
    prev_digest_object = raw.get("previousDigestS3Object")
    public_key_fingerprint = raw.get("digestPublicKeyFingerprint", "")
    account_id = raw.get("awsAccountId", "")

    # Combine log files from both sources
    log_files = log_files_raw if log_files_raw is not None else log_files_elk
    log_file_count = len(log_files) if log_files else 0

    # Window duration
    window_minutes = compute_window_minutes(start_time, end_time)

    score = 0
    signals = []

    # ── Anomaly 1: empty log window ────────────────────────────────────
    is_empty = (
        log_file_count == 0 and
        newest_event_time is None and
        oldest_event_time is None
    )

    if is_empty:
        if is_business_hours(end_time or ""):
            score += 40
            signals.append(
                f"+40  EMPTY LOG WINDOW during business hours — "
                f"zero events captured between {start_time} and {end_time}. "
                f"Possible StopLogging gap used to hide attacker activity."
            )
        else:
            score += 20
            signals.append(
                f"+20  EMPTY LOG WINDOW outside business hours — "
                f"zero events between {start_time} and {end_time}. "
                f"Lower risk but worth verifying no StopLogging was issued."
            )

    # ── Anomaly 2: chain break — missing previousDigest fields ─────────
    chain_broken = (
        not prev_hash_value or
        not prev_signature or
        not prev_digest_object
    )
    if chain_broken:
        missing = []
        if not prev_hash_value:
            missing.append("previousDigestHashValue")
        if not prev_signature:
            missing.append("previousDigestSignature")
        if not prev_digest_object:
            missing.append("previousDigestS3Object")
        score += 35
        signals.append(
            f"+35  HASH CHAIN BREAK — missing fields: {missing}. "
            f"The cryptographic chain linking this digest to the previous one "
            f"is incomplete. Could indicate a deleted or forged digest."
        )

    # ── Anomaly 3: signature algorithm downgrade ───────────────────────
    if sig_algorithm and sig_algorithm != EXPECTED_SIGNATURE_ALGORITHM:
        score += 30
        signals.append(
            f"+30  SIGNATURE ALGORITHM ANOMALY — got '{sig_algorithm}', "
            f"expected '{EXPECTED_SIGNATURE_ALGORITHM}'. "
            f"Non-standard algorithm could indicate a forged digest."
        )

    # ── Anomaly 4: abnormal window duration ────────────────────────────
    if window_minutes is not None:
        deviation = abs(window_minutes - EXPECTED_WINDOW_MINUTES)
        if deviation > WINDOW_TOLERANCE_MINUTES:
            score += 25
            signals.append(
                f"+25  ABNORMAL WINDOW — digest covers {window_minutes:.1f} "
                f"minutes instead of expected {EXPECTED_WINDOW_MINUTES}. "
                f"Deviation of {deviation:.1f} minutes suggests logging was "
                f"paused or the trail was stopped and restarted."
            )

    # ── Anomaly 5: digest bucket mismatch ─────────────────────────────
    if s3_bucket and prev_s3_bucket and s3_bucket != prev_s3_bucket:
        score += 20
        signals.append(
            f"+20  BUCKET MISMATCH — current digest in '{s3_bucket}' but "
            f"previous digest was in '{prev_s3_bucket}'. "
            f"Could indicate an attacker redirected digest storage."
        )

    # ── Anomaly 6: hash algorithm downgrade ───────────────────────────
    if prev_hash_algorithm and prev_hash_algorithm != EXPECTED_HASH_ALGORITHM:
        score += 15
        signals.append(
            f"+15  HASH ALGORITHM DOWNGRADE — previous digest used "
            f"'{prev_hash_algorithm}' instead of '{EXPECTED_HASH_ALGORITHM}'."
        )

    fields = {
        "account_id": account_id,
        "window_start": start_time,
        "window_end": end_time,
        "window_minutes": window_minutes,
        "log_file_count": log_file_count,
        "newest_event_time": newest_event_time,
        "oldest_event_time": oldest_event_time,
        "is_empty_window": is_empty,
        "signature_algorithm": sig_algorithm,
        "previous_hash_algorithm": prev_hash_algorithm,
        "prev_hash_value": prev_hash_value,
        "prev_digest_object": prev_digest_object,
        "public_key_fingerprint": public_key_fingerprint,
        "digest_s3_bucket": s3_bucket,
        "prev_s3_bucket": prev_s3_bucket,
        "elk_file_hash": deep_get(source, "file", "hash", "sha256"),
        "digest_s3_path": deep_get(source, "aws", "s3", "object", "key"),
        "timestamp": source.get("@timestamp", ""),
    }

    return score, signals, fields


def detect(elk_doc):
    """
    Returns (triggered, score, signals, fields).
    Alert threshold = 25 — lower than other skills because
    digest anomalies are inherently high-value signals.
    """
    source = extract_source(elk_doc)

    if not is_digest_document(source):
        return False, 0, ["Not a CloudTrail digest document — no aws.cloudtrail.digest fields found"], {}

    score, signals, fields = score_event(elk_doc)
    score = max(score, 0)
    triggered = score >= 25

    return triggered, score, signals, fields


# ── CLAUDE ENRICHMENT ─────────────────────────────────────────────────

def enrich_with_claude(score, signals, fields, raw):
    prompt_file = os.path.join(os.path.dirname(__file__), "prompt.txt")
    with open(prompt_file) as f:
        template = f.read()

    context = {
        "risk_score": score,
        "alert_threshold": 25,
        "risk_signals": signals,
        "parsed_fields": fields,
        "cloudtrail_digest_background": {
            "what_digest_files_are": (
                "CloudTrail generates a digest file every hour containing "
                "SHA-256 hashes of all log files from that window, plus a "
                "hash of the previous digest. This creates a tamper-evident "
                "hash chain across all your CloudTrail history."
            ),
            "what_empty_logfiles_means": (
                "logFiles=[] means CloudTrail captured ZERO events in this "
                "1-hour window. This could mean: (1) the trail was stopped "
                "via StopLogging, (2) the region genuinely had no activity, "
                "or (3) log files were deleted after the fact."
            ),
            "what_chain_break_means": (
                "If previousDigestHashValue or previousDigestSignature are "
                "missing, the cryptographic chain is broken. An attacker "
                "cannot forge valid digest files without AWS private keys, "
                "but they CAN delete digest files — breaking the chain."
            ),
            "why_this_matters": (
                "CloudTrail log integrity is your last line of defence in "
                "incident response. If an attacker can hide their CloudTrail "
                "activity, you have no forensic evidence of what they did."
            ),
        },
        "raw_digest": raw,
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

    window_start = fields.get("window_start", "unknown")
    window_end = fields.get("window_end", "unknown")
    log_count = fields.get("log_file_count", "?")
    window_mins = fields.get("window_minutes")
    account = fields.get("account_id", "unknown")

    print("Checking CloudTrail Digest")
    print(f"  Account:     {account}")
    print(f"  Window:      {window_start} → {window_end}")
    print(f"  Duration:    {f'{window_mins:.0f} min' if window_mins else 'unknown'}")
    print(f"  Log files:   {log_count}")
    print(f"  Sig algo:    {fields.get('signature_algorithm', 'unknown')}")
    print(f"  Score:       {score} / threshold 25")
    print()

    if signals:
        print("Anomalies evaluated:")
        for s in signals:
            print(f"  {s}")
        print()

    if triggered:
        raw = get_raw_digest(extract_source(elk_doc))
        print(f"[!] ALERT FIRED — digest integrity anomaly (score {score})")
        print("    Sending to Claude for analysis...\n")
        analysis = enrich_with_claude(score, signals, fields, raw)
        print("=" * 60)
        print(analysis)
        print("=" * 60)
    else:
        print(f"[OK] No critical anomaly — score {score} below threshold 25")

        if fields.get("is_empty_window"):
            print()
            print("[NOTICE] Log window is empty (logFiles=[]) but below alert threshold.")
            print(f"         Window: {window_start} → {window_end}")
            print("         Verify no StopLogging was issued during this period.")
            print("         Check: aws cloudtrail get-trail-status --name ELK-Monitoring")


if __name__ == "__main__":
    sample_file = os.path.join(os.path.dirname(__file__), "sample_event.json")
    with open(sample_file) as f:
        elk_doc = json.load(f)
    run(elk_doc)
