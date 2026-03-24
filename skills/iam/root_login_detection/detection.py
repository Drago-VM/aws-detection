import json
import anthropic
import os

# ── 1. DETECTION LOGIC ──────────────────────────────────────────────

def detect(event):
    """
    Fires when the AWS root account logs into the console.
    Root accounts should almost never be used directly.
    """

    if event.get("eventName") != "ConsoleLogin":
        return False

    user_type = event.get("userIdentity", {}).get("type", "")
    if user_type != "Root":
        return False

    login_result = event.get("responseElements", {}).get("ConsoleLogin", "")
    if login_result != "Success":
        return False

    return True


# ── 2. CLAUDE ENRICHMENT ─────────────────────────────────────────────

def enrich_with_claude(event):
    """
    Sends the suspicious event to Claude.
    Claude returns a plain English analyst report.
    """

    prompt_file = os.path.join(os.path.dirname(__file__), "prompt.txt")
    with open(prompt_file) as f:
        prompt_template = f.read()

    prompt = prompt_template.replace(
        "{event}",
        json.dumps(event, indent=2)
    )

    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    return response.content[0].text


# ── 3. RUN THE SKILL ─────────────────────────────────────────────────

def run(event):
    """
    Full skill run: detect → enrich → print result.
    """
    print(f"Checking event: {event.get('eventName')} "
          f"by {event.get('userIdentity', {}).get('type', 'unknown')}")

    if detect(event):
        print("\n[!] ALERT FIRED — Root login detected")
        print("    Sending to Claude for analysis...\n")
        analysis = enrich_with_claude(event)
        print("=" * 50)
        print(analysis)
        print("=" * 50)
    else:
        print("[OK] No alert — event looks normal\n")


# ── 4. TEST WITH SAMPLE EVENT ────────────────────────────────────────

if __name__ == "__main__":
    sample_file = os.path.join(os.path.dirname(__file__), "sample_event.json")
    with open(sample_file) as f:
        sample_event = json.load(f)

    run(sample_event) 
