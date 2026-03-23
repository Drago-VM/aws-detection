import os
import json
import anthropic

# ── CLAUDE CLIENT ───────────────────────────────────────────────
# You can set your Claude API key as an environment variable:
#   export ANTHROPIC_API_KEY="your_key_here"
# or in Windows PowerShell:
#   setx ANTHROPIC_API_KEY "your_key_here"

def get_client():
    """
    Returns an Anthropics client instance.
    """
    return anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# ── PROMPT HANDLER ──────────────────────────────────────────────

def enrich_with_claude(reason, details, raw_event, prompt_file=None, model="claude-sonnet-4-20250514"):
    """
    Sends an alert to Claude for enrichment/analysis.

    Parameters:
      - reason: string describing why this alert triggered
      - details: dict of parsed fields from ELK event
      - raw_event: original CloudTrail event JSON
      - prompt_file: optional path to a prompt template
      - model: Claude model to use (default = sonnet-4)

    Returns:
      - Claude's text response as string
    """
    if prompt_file and os.path.exists(prompt_file):
        with open(prompt_file, "r") as f:
            template = f.read()
    else:
        # default template if no prompt.txt provided
        template = (
            "You are a cloud security assistant. "
            "Analyze the following AWS detection alert:\n\n{event}\n\n"
            "Provide a brief human-readable explanation and any recommended actions."
        )

    context = {
        "alert_reason": reason,
        "parsed_fields": details,
        "raw_cloudtrail_event": raw_event
    }

    prompt = template.replace("{event}", json.dumps(context, indent=2))

    client = get_client()
    response = client.messages.create(
        model=model,
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )

    # Claude returns a dict; extract the text content
    if response and "content" in response and len(response["content"]) > 0:
        return response["content"][0].get("text", "")
    return "[ERROR] No response from Claude."
