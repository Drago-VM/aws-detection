import json
import anthropic
import os

# ── 1. DETECTION LOGIC ──────────────────────────────────────────────
# This function reads an AWS event and decides: is this suspicious?
# Returns True = alert fires, False = ignore it

def detect(event):
    """
    Fires when the AWS root account logs into the console.
    Root accounts should almost never be used directly.
    """

    # Must be a console login event
    if event.get("eventName") != "ConsoleLogin":
        return False

    # Must be the root account (not a regular IAM user)
    user_type = event.get("userIdentity", {}).get("type", "")
    if user_type != "Root":
        return False

    # Must be a successful login (not a failed attempt)
    login_result = event.get("responseElements", {}).get("ConsoleLogin", "")
    if login_result != "Success":
        return False

    # All checks passed — this is a suspicious root login
    return True


# ── 2. CLAUDE ENRICHMENT ─────────────────────────────────────────────
# This function sends the event to Claude and gets a plain English report

def enrich_with_claude(event):
    """
    Sends the suspicious event to Claude.
    Claude returns a plain English analyst report.
    """

    # Load the prompt template from prompt.txt
    prompt_file = os.path.join(os.path.dirname(__file__), "prompt.txt")
    with open(prompt_file) as f:
        prompt_template = f.read()

    # Replace {event} with the actual event data
    prompt = prompt_template.replace(
        "{event}",
        json.dumps(event, indent=2)
    )

    # Call the Claude API
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
# This is what runs when you execute this file directly

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
# This block only runs when you type: python detection.py

if __name__ == "__main__":
    # Load the sample event from sample_event.json
    sample_file = os.path.join(os.path.dirname(__file__), "sample_event.json")
    with open(sample_file) as f:
        sample_event = json.load(f)

    # Run the skill on it
    run(sample_event) 
