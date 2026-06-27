import os
import aiosqlite
from dotenv import load_dotenv

# Load env variables from backend/.env
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///../storage/soc.db")
db_file_rel = DATABASE_URL.replace("sqlite+aiosqlite:///", "")
DB_PATH = os.path.abspath(os.path.join(BASE_DIR, db_file_rel))

# Ensure storage directory exists
storage_dir = os.path.dirname(DB_PATH)
os.makedirs(storage_dir, exist_ok=True)

class Database:
    @staticmethod
    def get_connection():
        return aiosqlite.connect(DB_PATH)

    @classmethod
    async def execute(cls, query: str, params: tuple = ()):
        async with cls.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute(query, params) as cursor:
                await conn.commit()
                return await cursor.fetchall()

    @classmethod
    async def insert(cls, query: str, params: tuple = ()):
        async with cls.get_connection() as conn:
            async with conn.execute(query, params) as cursor:
                await conn.commit()
                return cursor.lastrowid

    @classmethod
    async def init_db(cls):
        async with cls.get_connection() as conn:
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS normalized_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                method TEXT NOT NULL,
                uri TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                user_agent TEXT,
                server TEXT NOT NULL,
                raw_log TEXT NOT NULL
            )
            """)
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                server TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                mitre_id TEXT NOT NULL,
                kill_chain_stage TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                threat_score INTEGER NOT NULL,
                raw_log TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Active'
            )
            """)
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                reason TEXT NOT NULL,
                threat_score INTEGER NOT NULL,
                blocked_by TEXT NOT NULL
            )
            """)
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                analyst_notes TEXT,
                assigned_analyst TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """)
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS incident_alerts (
                incident_id INTEGER,
                alert_id INTEGER,
                PRIMARY KEY (incident_id, alert_id),
                FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
                FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
            )
            """)
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS upload_jobs (
                job_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                format TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL,
                status TEXT NOT NULL,
                total_lines INTEGER DEFAULT 0,
                total_alerts INTEGER DEFAULT 0,
                completed_at TEXT,
                file_path TEXT NOT NULL
            )
            """)
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS offline_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                method TEXT NOT NULL,
                uri TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                user_agent TEXT,
                server TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                threat_score INTEGER NOT NULL,
                mitre_technique TEXT NOT NULL,
                kill_chain_stage TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Active',
                FOREIGN KEY(job_id) REFERENCES upload_jobs(job_id) ON DELETE CASCADE
            )
            """)
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS offline_analytics (
                job_id TEXT PRIMARY KEY,
                summary_json TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                FOREIGN KEY(job_id) REFERENCES upload_jobs(job_id) ON DELETE CASCADE
            )
            """)
            await conn.commit()
