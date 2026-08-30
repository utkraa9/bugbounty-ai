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
    V2.1 AI analysis for authorized security research.

    The model is explicitly instructed to separate:
    observations, security signals, potential issues,
    confidence, false-positive considerations, and
    safe manual verification.

    It does not directly interact with the target.
    """

    prompt = f"""
You are an AI security research assistant operating inside
an authorized bug-bounty workflow.

Analyze ONLY the reconnaissance evidence supplied below.

RECONNAISSANCE EVIDENCE:
{json.dumps(recon_data, indent=2)}

Your job is to help a human researcher prioritize what deserves
manual verification. Do not treat configuration observations as
confirmed vulnerabilities.

Return ONLY valid JSON with this exact structure:

{{
  "summary": "Short evidence-based summary",
  "observations": [
    {{
      "observation": "Directly observed fact",
      "evidence": "Specific evidence supporting the observation"
    }}
  ],
  "security_signals": [
    {{
      "signal": "Security-relevant signal",
      "reasoning": "Why the signal may matter",
      "confidence": 0.0
    }}
  ],
  "potential_findings": [
    {{
      "title": "Potential security issue",
      "category": "security category",
      "severity": "info|low|medium|high|critical",
      "confidence": 0.0,
      "evidence": [
        "Only evidence actually present in the reconnaissance data"
      ],
      "reasoning": "Evidence-based explanation",
      "false_positive_risk": "low|medium|high",
      "recommended_manual_check": "Safe, authorized verification step"
    }}
  ],
  "false_positive_considerations": [
    "Possible benign explanation or missing evidence"
  ],
  "priority": "low|medium|high",
  "analyst_notes": [
    "Important limitation, missing evidence, or context"
  ]
}}

STRICT RULES:

1. Evidence first.
   Never invent endpoints, parameters, credentials, payloads,
   responses, technologies, vulnerabilities, or attack results.

2. Observation is not vulnerability.
   A missing header, exposed technology version, open port,
   informational response, or configuration recommendation
   must not automatically be presented as an exploitable
   vulnerability.

3. Do not claim exploitation.
   Reconnaissance metadata alone cannot prove exploitability.

4. Severity must reflect demonstrated impact.
   When impact is unclear, prefer "info" or "low".

5. Confidence must represent confidence in the assessment,
   not confidence that exploitation is possible.

6. Every potential finding must contain evidence that exists
   in the supplied reconnaissance data.

7. If evidence is insufficient, explicitly say so and put the
   item into false_positive_considerations or analyst_notes.

8. Manual checks must remain within the authorized scope and
   must be safe verification steps. Do not suggest destructive
   actions, credential attacks, denial-of-service activity,
   persistence, or unauthorized access.

9. Avoid duplicate findings.
   Combine multiple observations when they represent the same
   underlying issue.

10. Distinguish hardening recommendations from vulnerabilities.
    Defense-in-depth improvements should normally be "info"
    unless the supplied evidence demonstrates meaningful
    security impact.

11. Do not use knowledge of a specific target from outside the
    supplied evidence to manufacture a finding.

12. If there are no credible potential findings, return an empty
    potential_findings array and explain why in analyst_notes.

Return JSON only. No Markdown. No commentary outside the JSON.
"""

    response = call_gemini(prompt)

    result = parse_json_response(response)

    # Keep a predictable shape for the frontend/API even when
    # Gemini returns incomplete JSON.
    if not isinstance(result, dict):
        return {
            "error": "Gemini returned an unexpected response format"
        }

    result.setdefault("summary", "")
    result.setdefault("observations", [])
    result.setdefault("security_signals", [])
    result.setdefault("potential_findings", [])
    result.setdefault("false_positive_considerations", [])
    result.setdefault("priority", "low")
    result.setdefault("analyst_notes", [])

    return result


def generate_bug_bounty_report(finding: dict) -> dict:
    """
    Generate a structured bug-bounty report from a
    human-confirmed finding.
    """

    prompt = f"""
You are preparing a professional bug-bounty report from a
human-confirmed finding.

Use ONLY the information contained in this finding:

{json.dumps(finding, indent=2)}

Return ONLY valid JSON using this exact structure:

{{
  "title": "Clear vulnerability or security issue title",
  "severity": "info|low|medium|high|critical",
  "summary": "Short executive summary",
  "affected_asset": "Affected asset",
  "technical_description": "Evidence-based technical explanation",
  "impact": "Realistic security impact",
  "evidence": "Relevant evidence actually present in the finding",
  "reproduction_steps": [
    "Only steps supported by the supplied finding"
  ],
  "remediation": "Recommended remediation",
  "limitations": [
    "Important limitation or uncertainty"
  ]
}}

Rules:

- Do not invent evidence.
- Do not invent request/response data.
- Do not invent endpoints, parameters, payloads, credentials,
  exploitation results, or reproduction details.
- Do not exaggerate severity or impact.
- If reproduction information is missing, explicitly state that.
- Preserve the distinction between hardening/configuration gaps
  and directly exploitable vulnerabilities.
- Keep the report suitable for responsible bug-bounty disclosure.
- Use the finding's actual affected asset and severity where
  supported.
- Return JSON only. No Markdown. No commentary outside the JSON.
"""

    response = call_gemini(prompt)

    return parse_json_response(response)
