import json
from pathlib import Path
from datetime import datetime, timezone

from .database import get_db


BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "data.json"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def migrate():
    if not DATA_FILE.exists():
        print("data.json not found.")
        return

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    programs = data.get("programs", {})
    scopes = data.get("scopes", {})
    candidates = data.get("candidates", {})
    findings = data.get("findings", {})

    with get_db() as db:

        # ---------- Programs ----------

        for program_id, program in programs.items():

            db.execute(
                """
                INSERT OR IGNORE INTO programs
                (id, name, platform, description, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    program_id,
                    program.get("name", ""),
                    program.get("platform", ""),
                    program.get("description", ""),
                    utc_now()
                )
            )

        # ---------- Scopes ----------

        for program_id, program_scopes in scopes.items():

            for scope in program_scopes:

                asset = scope.get("asset", "")

                # Avoid duplicate scope records
                existing = db.execute(
                    """
                    SELECT id
                    FROM scopes
                    WHERE program_id = ?
                    AND asset = ?
                    """,
                    (program_id, asset)
                ).fetchone()

                if existing:
                    continue

                db.execute(
                    """
                    INSERT INTO scopes
                    (program_id, asset, asset_type, notes, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        program_id,
                        asset,
                        scope.get("asset_type", "domain"),
                        scope.get("notes", ""),
                        utc_now()
                    )
                )

        # ---------- Candidates ----------

        for candidate_id, candidate in candidates.items():

            db.execute(
                """
                INSERT OR IGNORE INTO candidates
                (
                    id,
                    program_id,
                    asset,
                    title,
                    severity,
                    description,
                    evidence,
                    status,
                    reviewer_note,
                    reviewed_at,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate_id,
                    candidate.get("program_id", ""),
                    candidate.get("asset", ""),
                    candidate.get("title", ""),
                    candidate.get("severity", "low"),
                    candidate.get("description", ""),
                    candidate.get("evidence", ""),
                    candidate.get("status", "needs_review"),
                    candidate.get("reviewer_note", ""),
                    candidate.get("reviewed_at"),
                    candidate.get("created_at", utc_now())
                )
            )

        # ---------- Findings ----------

        for finding_id, finding in findings.items():

            db.execute(
                """
                INSERT OR IGNORE INTO findings
                (
                    id,
                    program_id,
                    candidate_id,
                    asset,
                    title,
                    severity,
                    description,
                    evidence,
                    status,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    finding.get("program_id", ""),
                    finding.get("candidate_id"),
                    finding.get("asset", ""),
                    finding.get("title", ""),
                    finding.get("severity", "low"),
                    finding.get("description", ""),
                    finding.get("evidence", ""),
                    finding.get("status", "confirmed"),
                    finding.get("created_at", utc_now())
                )
            )

    print("Migration completed successfully.")
    print(f"Programs migrated: {len(programs)}")
    print(f"Programs with scopes: {len(scopes)}")
    print(f"Candidates migrated: {len(candidates)}")
    print(f"Findings migrated: {len(findings)}")


if __name__ == "__main__":
    migrate()