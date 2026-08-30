from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from uuid import uuid4
from datetime import datetime, timezone
import json

from .database import get_db
from .recon import collect_http_metadata
from .ai import analyze_recon, generate_bug_bounty_report


app = FastAPI(
    title="BugBounty AI",
    version="0.8.0",
    description="AI-assisted bug bounty research platform"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Helpers ----------

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def normalize_asset(asset: str) -> str:
    asset = asset.strip().lower()

    if asset.startswith("https://"):
        asset = asset[8:]

    if asset.startswith("http://"):
        asset = asset[7:]

    asset = asset.split("/")[0]
    asset = asset.rstrip(".")

    return asset


def asset_matches(scope_asset: str, target_asset: str) -> bool:
    scope_asset = normalize_asset(scope_asset)
    target_asset = normalize_asset(target_asset)

    if scope_asset == target_asset:
        return True

    if scope_asset.startswith("*."):
        base_domain = scope_asset[2:]

        if target_asset.endswith("." + base_domain):
            return True

    return False


def is_asset_authorized(program_id: str, asset: str) -> bool:
    target = normalize_asset(asset)

    with get_db() as db:

        rows = db.execute(
            """
            SELECT asset
            FROM scopes
            WHERE program_id = ?
            """,
            (program_id,)
        ).fetchall()

    # Exclusions have priority
    for row in rows:

        scope_asset = normalize_asset(row["asset"])

        if scope_asset.startswith("!"):
            excluded_asset = scope_asset[1:]

            if asset_matches(excluded_asset, target):
                return False

    # Normal scope
    for row in rows:

        scope_asset = normalize_asset(row["asset"])

        if scope_asset.startswith("!"):
            continue

        if asset_matches(scope_asset, target):
            return True

    return False


def validate_target(asset: str):
    normalized = normalize_asset(asset)

    if not normalized:
        raise HTTPException(
            status_code=400,
            detail="Asset cannot be empty"
        )

    if "/" in normalized:
        raise HTTPException(
            status_code=400,
            detail="Invalid asset format"
        )

    return normalized


def program_exists(program_id: str) -> bool:

    with get_db() as db:

        row = db.execute(
            """
            SELECT id
            FROM programs
            WHERE id = ?
            """,
            (program_id,)
        ).fetchone()

    return row is not None


def row_to_dict(row):
    return dict(row) if row else None


# ---------- Data Models ----------

class ProgramCreate(BaseModel):
    name: str
    platform: str
    description: str = ""


class ScopeCreate(BaseModel):
    asset: str
    asset_type: str = "domain"
    notes: str = ""


class FindingCreate(BaseModel):
    asset: str
    title: str
    severity: str = "low"
    description: str = ""
    evidence: str = ""


class CandidateReview(BaseModel):
    status: str
    reviewer_note: str = ""


# ---------- Basic Routes ----------

@app.get("/")
def root():

    return {
        "name": "BugBounty AI",
        "version": "0.8.0",
        "status": "online",
        "storage": "sqlite"
    }


@app.get("/health")
def health():

    with get_db() as db:

        db.execute("SELECT 1")

    return {
        "status": "healthy",
        "database": "connected"
    }


# ---------- Programs ----------

@app.post("/programs")
def create_program(program: ProgramCreate):

    program_id = str(uuid4())

    with get_db() as db:

        db.execute(
            """
            INSERT INTO programs
            (id, name, platform, description, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                program_id,
                program.name,
                program.platform,
                program.description,
                utc_now()
            )
        )

    return {
        "id": program_id,
        "name": program.name,
        "platform": program.platform,
        "description": program.description
    }


@app.get("/programs")
def list_programs():

    with get_db() as db:

        rows = db.execute(
            """
            SELECT id, name, platform, description, created_at
            FROM programs
            ORDER BY created_at DESC
            """
        ).fetchall()

    return [dict(row) for row in rows]


# ---------- Scope ----------

@app.post("/programs/{program_id}/scope")
def add_scope(
    program_id: str,
    scope: ScopeCreate
):

    if not program_exists(program_id):

        raise HTTPException(
            status_code=404,
            detail="Program not found"
        )

    with get_db() as db:

        cursor = db.execute(
            """
            INSERT INTO scopes
            (program_id, asset, asset_type, notes, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                program_id,
                scope.asset,
                scope.asset_type,
                scope.notes,
                utc_now()
            )
        )

        scope_id = cursor.lastrowid

    return {
        "id": scope_id,
        "program_id": program_id,
        "asset": scope.asset,
        "asset_type": scope.asset_type,
        "notes": scope.notes
    }


@app.get("/programs/{program_id}/scope")
def get_scope(program_id: str):

    if not program_exists(program_id):

        raise HTTPException(
            status_code=404,
            detail="Program not found"
        )

    with get_db() as db:

        rows = db.execute(
            """
            SELECT id, asset, asset_type, notes, created_at
            FROM scopes
            WHERE program_id = ?
            ORDER BY id
            """,
            (program_id,)
        ).fetchall()

    return {
        "program_id": program_id,
        "scope": [dict(row) for row in rows]
    }


# ---------- Scope Check ----------

@app.get("/scope/check/{program_id}")
def check_scope(
    program_id: str,
    asset: str
):

    if not program_exists(program_id):

        raise HTTPException(
            status_code=404,
            detail="Program not found"
        )

    return {
        "asset": asset,
        "authorized": is_asset_authorized(
            program_id,
            asset
        )
    }


# ---------- Recon ----------

@app.get("/recon/{program_id}")
def run_recon(
    program_id: str,
    asset: str
):

    if not program_exists(program_id):

        raise HTTPException(
            status_code=404,
            detail="Program not found"
        )

    target = validate_target(asset)

    if not is_asset_authorized(
        program_id,
        target
    ):

        raise HTTPException(
            status_code=403,
            detail="Asset is outside authorized scope"
        )

    try:

        result = collect_http_metadata(target)

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )

    # Store recon history
    recon_id = str(uuid4())

    with get_db() as db:

        db.execute(
            """
            INSERT INTO recon_runs
            (id, program_id, asset, recon_data, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                recon_id,
                program_id,
                target,
                json.dumps(result),
                utc_now()
            )
        )

    return {
        "id": recon_id,
        "program_id": program_id,
        "authorized": True,
        "recon": result
    }


# ---------- Recon History ----------

@app.get("/programs/{program_id}/recon")
def list_recon_runs(program_id: str):

    if not program_exists(program_id):

        raise HTTPException(
            status_code=404,
            detail="Program not found"
        )

    with get_db() as db:

        rows = db.execute(
            """
            SELECT id, program_id, asset, recon_data, created_at
            FROM recon_runs
            WHERE program_id = ?
            ORDER BY created_at DESC
            """,
            (program_id,)
        ).fetchall()

    results = []

    for row in rows:

        item = dict(row)

        try:
            item["recon_data"] = json.loads(
                item["recon_data"]
            )
        except json.JSONDecodeError:
            pass

        results.append(item)

    return results


# ---------- AI Analysis ----------

@app.get("/analyze/{program_id}")
def analyze_target(
    program_id: str,
    asset: str
):

    if not program_exists(program_id):

        raise HTTPException(
            status_code=404,
            detail="Program not found"
        )

    target = validate_target(asset)

    if not is_asset_authorized(
        program_id,
        target
    ):

        raise HTTPException(
            status_code=403,
            detail="Asset is outside authorized scope"
        )

    try:

        recon_result = collect_http_metadata(target)

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )

    # Store recon
    recon_id = str(uuid4())

    with get_db() as db:

        db.execute(
            """
            INSERT INTO recon_runs
            (id, program_id, asset, recon_data, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                recon_id,
                program_id,
                target,
                json.dumps(recon_result),
                utc_now()
            )
        )

    # Gemini analysis
    try:

        analysis = analyze_recon(
            recon_result
        )

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail=f"AI analysis failed: {str(exc)}"
        )

    # Store analysis
    analysis_id = str(uuid4())

    with get_db() as db:

        db.execute(
            """
            INSERT INTO analyses
            (id, program_id, asset, recon_run_id,
             analysis_data, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                analysis_id,
                program_id,
                target,
                recon_id,
                json.dumps(analysis),
                utc_now()
            )
        )

    return {
        "id": analysis_id,
        "program_id": program_id,
        "asset": target,
        "authorized": True,
        "recon_run_id": recon_id,
        "recon": recon_result,
        "analysis": analysis
    }


# ---------- Analysis History ----------

@app.get("/programs/{program_id}/analyses")
def list_analyses(program_id: str):

    if not program_exists(program_id):

        raise HTTPException(
            status_code=404,
            detail="Program not found"
        )

    with get_db() as db:

        rows = db.execute(
            """
            SELECT
                id,
                program_id,
                asset,
                recon_run_id,
                analysis_data,
                created_at
            FROM analyses
            WHERE program_id = ?
            ORDER BY created_at DESC
            """,
            (program_id,)
        ).fetchall()

    results = []

    for row in rows:

        item = dict(row)

        try:
            item["analysis_data"] = json.loads(
                item["analysis_data"]
            )
        except json.JSONDecodeError:
            pass

        results.append(item)

    return results


# ---------- Candidates ----------

@app.post("/candidates/{program_id}")
def create_candidate(
    program_id: str,
    finding: FindingCreate
):

    if not program_exists(program_id):

        raise HTTPException(
            status_code=404,
            detail="Program not found"
        )

    if not is_asset_authorized(
        program_id,
        finding.asset
    ):

        raise HTTPException(
            status_code=403,
            detail="Asset is outside authorized scope"
        )

    candidate_id = str(uuid4())

    with get_db() as db:

        db.execute(
            """
            INSERT INTO candidates
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
                program_id,
                finding.asset,
                finding.title,
                finding.severity,
                finding.description,
                finding.evidence,
                "needs_review",
                "",
                None,
                utc_now()
            )
        )

    return {
        "id": candidate_id,
        "program_id": program_id,
        "asset": finding.asset,
        "title": finding.title,
        "severity": finding.severity,
        "description": finding.description,
        "evidence": finding.evidence,
        "status": "needs_review",
        "reviewer_note": "",
        "reviewed_at": None
    }


@app.get("/programs/{program_id}/candidates")
def list_candidates(program_id: str):

    if not program_exists(program_id):

        raise HTTPException(
            status_code=404,
            detail="Program not found"
        )

    with get_db() as db:

        rows = db.execute(
            """
            SELECT *
            FROM candidates
            WHERE program_id = ?
            ORDER BY created_at DESC
            """,
            (program_id,)
        ).fetchall()

    return [dict(row) for row in rows]


@app.get("/candidates/{candidate_id}")
def get_candidate(candidate_id: str):

    with get_db() as db:

        row = db.execute(
            """
            SELECT *
            FROM candidates
            WHERE id = ?
            """,
            (candidate_id,)
        ).fetchone()

    if not row:

        raise HTTPException(
            status_code=404,
            detail="Candidate not found"
        )

    return dict(row)


# ---------- Candidate Review ----------

@app.patch("/candidates/{candidate_id}/review")
def review_candidate(
    candidate_id: str,
    review: CandidateReview
):

    if review.status not in [
        "confirmed",
        "rejected"
    ]:

        raise HTTPException(
            status_code=400,
            detail="Status must be 'confirmed' or 'rejected'"
        )

    with get_db() as db:

        candidate = db.execute(
            """
            SELECT *
            FROM candidates
            WHERE id = ?
            """,
            (candidate_id,)
        ).fetchone()

        if not candidate:

            raise HTTPException(
                status_code=404,
                detail="Candidate not found"
            )

        if candidate["status"] != "needs_review":

            raise HTTPException(
                status_code=409,
                detail="Candidate has already been reviewed"
            )

        db.execute(
            """
            UPDATE candidates
            SET
                status = ?,
                reviewer_note = ?,
                reviewed_at = ?
            WHERE id = ?
            """,
            (
                review.status,
                review.reviewer_note,
                utc_now(),
                candidate_id
            )
        )

        updated = db.execute(
            """
            SELECT *
            FROM candidates
            WHERE id = ?
            """,
            (candidate_id,)
        ).fetchone()

    return dict(updated)


# ---------- Confirm Candidate ----------

@app.post("/candidates/{candidate_id}/confirm")
def confirm_candidate(candidate_id: str):

    with get_db() as db:

        candidate = db.execute(
            """
            SELECT *
            FROM candidates
            WHERE id = ?
            """,
            (candidate_id,)
        ).fetchone()

        if not candidate:

            raise HTTPException(
                status_code=404,
                detail="Candidate not found"
            )

        if candidate["status"] != "confirmed":

            raise HTTPException(
                status_code=409,
                detail="Candidate must be reviewed and confirmed first"
            )

        if not is_asset_authorized(
            candidate["program_id"],
            candidate["asset"]
        ):

            raise HTTPException(
                status_code=403,
                detail="Asset is outside authorized scope"
            )

        finding_id = str(uuid4())

        db.execute(
            """
            INSERT INTO findings
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
                candidate["program_id"],
                candidate_id,
                candidate["asset"],
                candidate["title"],
                candidate["severity"],
                candidate["description"],
                candidate["evidence"],
                "confirmed",
                utc_now()
            )
        )

        finding = db.execute(
            """
            SELECT *
            FROM findings
            WHERE id = ?
            """,
            (finding_id,)
        ).fetchone()

    return dict(finding)


# ---------- Findings ----------

@app.get("/programs/{program_id}/findings")
def list_findings(program_id: str):

    if not program_exists(program_id):

        raise HTTPException(
            status_code=404,
            detail="Program not found"
        )

    with get_db() as db:

        rows = db.execute(
            """
            SELECT *
            FROM findings
            WHERE program_id = ?
            ORDER BY created_at DESC
            """,
            (program_id,)
        ).fetchall()

    return [dict(row) for row in rows]


@app.get("/findings/{finding_id}")
def get_finding(finding_id: str):

    with get_db() as db:

        row = db.execute(
            """
            SELECT *
            FROM findings
            WHERE id = ?
            """,
            (finding_id,)
        ).fetchone()

    if not row:

        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    return dict(row)


# ---------- Reports ----------

@app.get("/reports/{finding_id}")
def generate_report(finding_id: str):

    with get_db() as db:

        row = db.execute(
            """
            SELECT *
            FROM findings
            WHERE id = ?
            """,
            (finding_id,)
        ).fetchone()

    if not row:

        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    finding = dict(row)

    if finding.get("status") != "confirmed":

        raise HTTPException(
            status_code=409,
            detail="Only confirmed findings can generate reports"
        )

    if not is_asset_authorized(
        finding["program_id"],
        finding["asset"]
    ):

        raise HTTPException(
            status_code=403,
            detail="Asset is outside authorized scope"
        )

    try:

        report = generate_bug_bounty_report(
            finding
        )

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail=f"Report generation failed: {str(exc)}"
        )

    report_id = str(uuid4())

    with get_db() as db:

        db.execute(
            """
            INSERT INTO reports
            (id, finding_id, report_data, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                report_id,
                finding_id,
                json.dumps(report),
                utc_now()
            )
        )

    return {
        "id": report_id,
        "finding_id": finding_id,
        "program_id": finding["program_id"],
        "asset": finding["asset"],
        "status": "confirmed",
        "report": report
    }


# ---------- Report History ----------

@app.get("/findings/{finding_id}/reports")
def list_reports(finding_id: str):

    with get_db() as db:

        finding = db.execute(
            """
            SELECT id
            FROM findings
            WHERE id = ?
            """,
            (finding_id,)
        ).fetchone()

        if not finding:

            raise HTTPException(
                status_code=404,
                detail="Finding not found"
            )

        rows = db.execute(
            """
            SELECT id, finding_id, report_data, created_at
            FROM reports
            WHERE finding_id = ?
            ORDER BY created_at DESC
            """,
            (finding_id,)
        ).fetchall()

    results = []

    for row in rows:

        item = dict(row)

        try:
            item["report_data"] = json.loads(
                item["report_data"]
            )
        except json.JSONDecodeError:
            pass

        results.append(item)

    return results