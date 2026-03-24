import os
import time
import json
import anthropic

# ── CONFIGURATION 

MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 1024
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 2


# ── CORE API CALL 

def ask_claude(prompt: str, system_prompt: str = None) -> dict:
    """
    Sends a prompt to Claude and returns a structured response dict.

    Args:
        prompt:        The user message — typically your detection context
        system_prompt: Optional system role instruction (overrides default)

    Returns:
        {
            "success":    bool,
            "text":       str,   # Claude's response text
            "model":      str,   # model used
            "input_tokens":  int,
            "output_tokens": int,
            "error":      str | None
        }

    Example:
        result = ask_claude(prompt)
        if result["success"]:
            print(result["text"])
        else:
            print(f"Claude error: {result['error']}")
    """
    if not system_prompt:
        system_prompt = (
            "You are an expert cloud security analyst specialising in AWS "
            "threat detection and incident response. You analyse CloudTrail "
            "logs ingested via Filebeat into Elasticsearch/ELK. "
            "Be concise, practical, and write for a working security analyst."
        )

    client = anthropic.Anthropic()

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            return {
                "success": True,
                "text": response.content[0].text,
                "model": response.model,
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "error": None,
            }

        except anthropic.RateLimitError as e:
            if attempt < MAX_RETRIES:
                wait = RETRY_DELAY_SECONDS * attempt
                print(f"    [claude_utils] Rate limit hit — retrying in {wait}s "
                      f"(attempt {attempt}/{MAX_RETRIES})")
                time.sleep(wait)
            else:
                return _error_response(f"Rate limit exceeded after {MAX_RETRIES} attempts: {e}")

        except anthropic.APIConnectionError as e:
            if attempt < MAX_RETRIES:
                wait = RETRY_DELAY_SECONDS * attempt
                print(f"    [claude_utils] Connection error — retrying in {wait}s")
                time.sleep(wait)
            else:
                return _error_response(f"Connection failed after {MAX_RETRIES} attempts: {e}")

        except anthropic.AuthenticationError as e:
            # No point retrying auth errors — fail immediately
            return _error_response(
                f"Authentication failed — check ANTHROPIC_API_KEY env var: {e}"
            )

        except Exception as e:
            return _error_response(f"Unexpected error calling Claude API: {e}")

    return _error_response("Max retries exhausted")


def _error_response(message: str) -> dict:
    """Returns a standardised error response dict."""
    return {
        "success": False,
        "text": "",
        "model": MODEL,
        "input_tokens": 0,
        "output_tokens": 0,
        "error": message,
    }


# ── PROMPT LOADER 

def load_prompt(skill_dir: str, context: dict) -> str:
    """
    Loads prompt.txt from a skill directory and injects context.

    Args:
        skill_dir:  Absolute path to the skill folder (__file__ dir)
        context:    Dict to JSON-serialise into the {event} placeholder

    Returns:
        Filled prompt string ready to send to Claude.

    Example:
        prompt = load_prompt(
            os.path.dirname(__file__),
            {"alert": "root login", "event": raw_event}
        )
    """
    prompt_path = os.path.join(skill_dir, "prompt.txt")

    if not os.path.exists(prompt_path):
        raise FileNotFoundError(
            f"prompt.txt not found at {prompt_path}. "
            f"Every skill must have a prompt.txt file."
        )

    with open(prompt_path) as f:
        template = f.read()

    return template.replace("{event}", json.dumps(context, indent=2))


# ── OUTPUT FORMATTER 

def format_alert_output(
    skill_name: str,
    triggered: bool,
    reason: str,
    claude_result: dict = None,
    score: int = None,
    threshold: int = None,
) -> None:
    """
    Prints a standardised alert output to the terminal.

    Used by the run() function in every skill for consistent output.

    Args:
        skill_name:    Human-readable name of the skill
        triggered:     Whether the alert fired
        reason:        Short reason string (why it fired or why not)
        claude_result: Return value from ask_claude() — optional
        score:         Risk score if using scoring model — optional
        threshold:     Alert threshold if using scoring model — optional
    """
    divider = "=" * 60

    if triggered:
        print(f"\n[!] ALERT — {skill_name}")
        if score is not None and threshold is not None:
            print(f"    Score: {score} / threshold {threshold}")
        print(f"    {reason}")

        if claude_result:
            if claude_result["success"]:
                print(f"\n    Claude analysis ({claude_result['output_tokens']} tokens):\n")
                print(divider)
                print(claude_result["text"])
                print(divider)
            else:
                print(f"\n    [!] Claude enrichment failed: {claude_result['error']}")
                print(f"    Raw alert still valid — investigate manually.")
    else:
        print(f"[OK] {skill_name} — {reason}")



def extract_source(elk_doc: dict) -> dict:
    """Unwraps _source if present, otherwise returns doc as-is."""
    return elk_doc.get("_source", elk_doc)


def get_raw_cloudtrail(source: dict) -> dict:
    """
    Parses the raw CloudTrail JSON string from event.original.

    ELK indexes most fields but stores the complete original event
    as a JSON string in event.original. Some fields (like tlsDetails,
    sharedEventID) only exist in the raw string.
    """
    raw_str = source.get("event", {}).get("original", "")
    if raw_str:
        try:
            return json.loads(raw_str)
        except (json.JSONDecodeError, TypeError):
            pass
    return {}


def deep_get(obj: dict, *keys) -> object:
    """
    Safely traverses nested dicts without KeyError.

    Example:
        deep_get(source, "source", "geo", "country_name") → "India"
        deep_get(source, "missing", "key") → None
    """
    for key in keys:
        if isinstance(obj, dict):
            obj = obj.get(key)
        else:
            return None
    return obj


def extract_kms_account_id(kms_key_arn: str) -> str | None:
    """
    Extracts account ID from a KMS key ARN.
    arn:aws:kms:us-east-1:851725491209:key/abc → "851725491209"
    """
    if not kms_key_arn:
        return None
    parts = kms_key_arn.split(":")
    return parts[4] if len(parts) >= 5 else None


def is_external_ip(ip: str) -> bool:
    """
    Returns True if the IP is not from a trusted internal or AWS range.
    Used by S3 exfiltration and IAM recon skills.
    """
    if not ip:
        return False
    trusted_prefixes = (
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168.",
        "54.239.", "54.242.", "52.95.", "52.46.",
    )
    return not any(ip.startswith(p) for p in trusted_prefixes)


def is_aws_service_caller(source: dict) -> bool:
    """
    Returns True if the caller is an AWS service (not human/IAM user).
    Used by KMS and S3 PutObject skills to whitelist service writes.
    """
    identity_type = deep_get(
        source, "aws", "cloudtrail", "user_identity", "type"
    )
    if identity_type == "AWSService":
        return True
    raw = get_raw_cloudtrail(source)
    return raw.get("userIdentity", {}).get("type") == "AWSService"


def is_outside_business_hours(timestamp_str: str,
                               start_hour: int = 6,
                               end_hour: int = 22) -> bool:
    """
    Returns True if timestamp falls outside UTC business hours.
    Used by IAM recon and KMS skills for off-hours scoring.
    """
    try:
        hour = int(timestamp_str[11:13])
        return hour < start_hour or hour >= end_hour
    except (TypeError, IndexError, ValueError):
        return False



if __name__ == "__main__":
    print("Testing Claude API connection...")
    print(f"Model: {MODEL}")
    print()

    result = ask_claude(
        "You are being tested. Reply with exactly: "
        "'claude_utils.py loaded successfully — API key is working.'"
    )

    if result["success"]:
        print(result["text"])
        print()
        print(f"Tokens used — input: {result['input_tokens']}, "
              f"output: {result['output_tokens']}")
    else:
        print(f"FAILED: {result['error']}")
        print()
        print("Fix: make sure ANTHROPIC_API_KEY is set in your environment")
        print("  Windows: setx ANTHROPIC_API_KEY your-key-here")
        print("  Mac/Linux: export ANTHROPIC_API_KEY=your-key-here")
