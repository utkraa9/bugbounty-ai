import os
import json

from dotenv import load_dotenv
from google import genai


load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise RuntimeError(
        "GEMINI_API_KEY is not configured in .env"
    )


client = genai.Client(api_key=API_KEY)

MODEL = "gemini-3.6-flash"


def call_gemini(prompt: str) -> str:
    """
    Send a prompt to Gemini and return its text output.
    """

    interaction = client.interactions.create(
        model=MODEL,
        input=prompt
    )

    return interaction.output_text.strip()


def parse_json_response(text: str) -> dict:
    """
    Safely parse JSON returned by Gemini.
    """

    text = text.strip()

    if text.startswith("```"):
        lines = text.splitlines()

        if lines and lines[0].startswith("```"):
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        text = "\n".join(lines).strip()

        if text.lower().startswith("json"):
            text = text[4:].strip()

    try:
        return json.loads(text)

    except json.JSONDecodeError:
        return {
            "error": "Gemini returned invalid JSON",
            "raw_response": text
        }


def analyze_recon(recon_data: dict) -> dict:
    """
    Analyze authorized reconnaissance evidence.

    This function does not directly interact with the target.
    """

    prompt = f"""
You are a security research assistant working inside an
authorized bug-bounty workflow.

Analyze the following reconnaissance evidence:

{json.dumps(recon_data, indent=2)}

Return ONLY valid JSON:

{{
  "summary": "Short summary of observations",
  "interesting_signals": [
    "Observation"
  ],
  "potential_findings": [
    {{
      "title": "Potential issue",
      "severity": "info|low|medium|high|critical",
      "confidence": 0.0,
      "reasoning": "Evidence-based reasoning",
      "recommended_manual_check": "Safe authorized check"
    }}
  ],
  "false_positive_considerations": [
    "Possible benign explanation"
  ]
}}

Rules:
- Do not claim a vulnerability is confirmed from metadata alone.
- Separate observations from confirmed vulnerabilities.
- Be evidence-driven.
- Do not perform unauthorized access.
- Recommendations must remain within authorized scope.
"""

    response = call_gemini(prompt)

    return parse_json_response(response)


def generate_bug_bounty_report(finding: dict) -> dict:
    """
    Generate a structured bug-bounty report from a
    human-confirmed finding.
    """

    prompt = f"""
You are preparing a professional bug-bounty report.

The following finding has already been reviewed and confirmed
by the researcher:

{json.dumps(finding, indent=2)}

Create a concise, professional report.

Return ONLY valid JSON using this structure:

{{
  "title": "Clear vulnerability title",
  "severity": "info|low|medium|high|critical",
  "summary": "Short executive summary",
  "affected_asset": "Affected asset",
  "technical_description": "Detailed technical explanation",
  "impact": "Realistic security impact",
  "evidence": "Relevant evidence from the finding",
  "reproduction_steps": [
    "Step 1",
    "Step 2"
  ],
  "remediation": "Recommended remediation",
  "limitations": [
    "Important limitation or uncertainty"
  ]
}}

Rules:
- Do not invent evidence.
- Do not invent reproduction steps that are not supported
  by the supplied finding.
- Do not exaggerate severity or impact.
- If information is missing, clearly say so.
- Keep the report suitable for responsible bug-bounty
  disclosure.
"""

    response = call_gemini(prompt)

    return parse_json_response(response)