import sqlite3
from pathlib import Path
from contextlib import contextmanager


# ---------- Database Location ----------

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "bugbounty.db"


# ---------- Connection ----------

@contextmanager
def get_db():
    connection = sqlite3.connect(DB_FILE)

    connection.row_factory = sqlite3.Row

    try:
        yield connection
        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


# ---------- Database Initialization ----------

def init_db():
    with get_db() as db:

        db.execute("""
            CREATE TABLE IF NOT EXISTS programs (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                platform TEXT NOT NULL,
                description TEXT DEFAULT '',
                created_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS scopes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id TEXT NOT NULL,
                asset TEXT NOT NULL,
                asset_type TEXT DEFAULT 'domain',
                notes TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                FOREIGN KEY (program_id)
                    REFERENCES programs(id)
                    ON DELETE CASCADE
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS candidates (
                id TEXT PRIMARY KEY,
                program_id TEXT NOT NULL,
                asset TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT DEFAULT '',
                evidence TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'needs_review',
                reviewer_note TEXT DEFAULT '',
                reviewed_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (program_id)
                    REFERENCES programs(id)
                    ON DELETE CASCADE
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                program_id TEXT NOT NULL,
                candidate_id TEXT,
                asset TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT DEFAULT '',
                evidence TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'confirmed',
                created_at TEXT NOT NULL,
                FOREIGN KEY (program_id)
                    REFERENCES programs(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (candidate_id)
                    REFERENCES candidates(id)
                    ON DELETE SET NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS recon_runs (
                id TEXT PRIMARY KEY,
                program_id TEXT NOT NULL,
                asset TEXT NOT NULL,
                recon_data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (program_id)
                    REFERENCES programs(id)
                    ON DELETE CASCADE
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                program_id TEXT NOT NULL,
                asset TEXT NOT NULL,
                recon_run_id TEXT,
                analysis_data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (program_id)
                    REFERENCES programs(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (recon_run_id)
                    REFERENCES recon_runs(id)
                    ON DELETE SET NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                report_data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (finding_id)
                    REFERENCES findings(id)
                    ON DELETE CASCADE
            )
        """)


# ---------- Initialize Automatically ----------

init_db()