import json
import logging
import os
from datetime import datetime, timezone

import aiosqlite

from config import config

logger = logging.getLogger(__name__)

CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS scan_sessions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    total_prefixes INTEGER DEFAULT 0,
    total_ips      INTEGER DEFAULT 0,
    status         TEXT DEFAULT 'running',
    session_type   TEXT DEFAULT 'full'
);

CREATE TABLE IF NOT EXISTS prefix_results (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   INTEGER NOT NULL REFERENCES scan_sessions(id),
    prefix       TEXT NOT NULL,
    scanned_at   TEXT NOT NULL,
    total_reports INTEGER DEFAULT 0,
    reported_ips INTEGER DEFAULT 0,
    max_score    INTEGER DEFAULT 0,
    raw_json     TEXT
);

CREATE TABLE IF NOT EXISTS ip_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER NOT NULL REFERENCES scan_sessions(id),
    ip_address    TEXT NOT NULL,
    prefix        TEXT NOT NULL,
    scanned_at    TEXT NOT NULL,
    abuse_score   INTEGER DEFAULT 0,
    num_reports   INTEGER DEFAULT 0,
    last_reported TEXT,
    country_code  TEXT,
    categories    TEXT,
    voidip_score  REAL DEFAULT 0.0,
    voidip_tags   TEXT
);

CREATE TABLE IF NOT EXISTS category_stats (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER NOT NULL REFERENCES scan_sessions(id),
    category_id   INTEGER NOT NULL,
    category_name TEXT NOT NULL,
    ip_count      INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ip_results_session ON ip_results(session_id);
CREATE INDEX IF NOT EXISTS idx_ip_results_score   ON ip_results(session_id, abuse_score DESC);
CREATE INDEX IF NOT EXISTS idx_prefix_session     ON prefix_results(session_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def init_db() -> None:
    os.makedirs(os.path.dirname(config.db_path) or ".", exist_ok=True)
    async with aiosqlite.connect(config.db_path) as db:
        await db.executescript(CREATE_TABLES)
        # migrate: add session_type if missing (safe on existing DB)
        try:
            await db.execute(
                "ALTER TABLE scan_sessions ADD COLUMN session_type TEXT DEFAULT 'full'"
            )
            await db.commit()
        except Exception:
            pass
    logger.info("Database initialized at %s", config.db_path)


async def create_session(session_type: str = "full") -> int:
    async with aiosqlite.connect(config.db_path) as db:
        cursor = await db.execute(
            "INSERT INTO scan_sessions (started_at, status, session_type) VALUES (?, 'running', ?)",
            (_now(), session_type),
        )
        await db.commit()
        return cursor.lastrowid


async def finish_session(
    session_id: int, total_prefixes: int, total_ips: int, status: str
) -> None:
    async with aiosqlite.connect(config.db_path) as db:
        await db.execute(
            """UPDATE scan_sessions
               SET finished_at=?, total_prefixes=?, total_ips=?, status=?
               WHERE id=?""",
            (_now(), total_prefixes, total_ips, status, session_id),
        )
        await db.commit()


async def save_prefix_result(session_id: int, prefix: str, data: dict) -> None:
    async with aiosqlite.connect(config.db_path) as db:
        await db.execute(
            """INSERT INTO prefix_results
               (session_id, prefix, scanned_at, total_reports, reported_ips, max_score, raw_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id,
                prefix,
                _now(),
                data.get("total_reports", 0),
                data.get("reported_ips", 0),
                data.get("max_score", 0),
                json.dumps(data.get("raw", {})),
            ),
        )
        await db.commit()


async def save_ip_results(session_id: int, prefix: str, ip_list: list[dict]) -> None:
    if not ip_list:
        return
    rows = [
        (
            session_id,
            ip["ip_address"],
            prefix,
            _now(),
            ip.get("abuse_score", 0),
            ip.get("num_reports", 0),
            ip.get("last_reported"),
            ip.get("country_code"),
            json.dumps(ip.get("categories", [])),
            ip.get("voidip_score", 0.0),
            json.dumps(ip.get("voidip_tags", [])),
        )
        for ip in ip_list
    ]
    async with aiosqlite.connect(config.db_path) as db:
        await db.executemany(
            """INSERT INTO ip_results
               (session_id, ip_address, prefix, scanned_at, abuse_score, num_reports,
                last_reported, country_code, categories, voidip_score, voidip_tags)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        await db.commit()


async def save_category_stats(
    session_id: int, stats: dict[int, tuple[str, int]]
) -> None:
    """stats: {category_id: (category_name, ip_count)}"""
    rows = [
        (session_id, cat_id, name, count) for cat_id, (name, count) in stats.items()
    ]
    async with aiosqlite.connect(config.db_path) as db:
        await db.executemany(
            "INSERT INTO category_stats (session_id, category_id, category_name, ip_count) VALUES (?,?,?,?)",
            rows,
        )
        await db.commit()


async def get_latest_session() -> dict | None:
    """Return the most recent completed full-scan session."""
    async with aiosqlite.connect(config.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM scan_sessions WHERE status='done' AND session_type='full' ORDER BY id DESC LIMIT 1"
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_session_summary(session_id: int) -> dict:
    async with aiosqlite.connect(config.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT
                COUNT(*) as total_reported_ips,
                SUM(num_reports) as total_reports,
                AVG(abuse_score) as avg_score,
                MAX(abuse_score) as max_score
               FROM ip_results WHERE session_id=?""",
            (session_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else {}


async def get_top_offenders(session_id: int, limit: int) -> list[dict]:
    async with aiosqlite.connect(config.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT * FROM ip_results WHERE session_id=?
               ORDER BY abuse_score DESC, num_reports DESC LIMIT ?""",
            (session_id, limit),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_category_breakdown(session_id: int) -> list[dict]:
    async with aiosqlite.connect(config.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT * FROM category_stats WHERE session_id=?
               ORDER BY ip_count DESC""",
            (session_id,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_session_history(limit: int = 7) -> list[dict]:
    async with aiosqlite.connect(config.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT * FROM scan_sessions
               WHERE status IN ('done','failed')
               ORDER BY id DESC LIMIT ?""",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_latest_done_session() -> dict | None:
    """Return most recent done session of any type (full or solo)."""
    async with aiosqlite.connect(config.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM scan_sessions WHERE status='done' ORDER BY id DESC LIMIT 1"
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_high_score_ips(session_id: int, threshold: int, limit: int = 15) -> list[dict]:
    async with aiosqlite.connect(config.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT * FROM ip_results
               WHERE session_id=? AND abuse_score >= ?
               ORDER BY abuse_score DESC LIMIT ?""",
            (session_id, threshold, limit),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_ips_for_nullroute(session_id: int, min_score: int) -> list[dict]:
    async with aiosqlite.connect(config.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT ip_address, abuse_score, num_reports, country_code, prefix
               FROM ip_results
               WHERE session_id=? AND abuse_score >= ?
               ORDER BY abuse_score DESC""",
            (session_id, min_score),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_weekly_stats() -> list[dict]:
    """Stats grouped by ISO week for the last 4 full-scan weeks."""
    async with aiosqlite.connect(config.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT
                strftime('%Y-W%W', s.started_at)  AS week_label,
                COUNT(DISTINCT s.id)               AS scan_count,
                COALESCE(SUM(s.total_ips), 0)      AS total_ips,
                COUNT(ir.id)                       AS reported_ips,
                ROUND(AVG(ir.abuse_score), 1)      AS avg_score,
                COALESCE(MAX(ir.abuse_score), 0)   AS max_score,
                COALESCE(SUM(ir.num_reports), 0)   AS total_reports
            FROM scan_sessions s
            LEFT JOIN ip_results ir ON ir.session_id = s.id
            WHERE s.status = 'done'
              AND s.session_type = 'full'
              AND s.started_at >= datetime('now', '-28 days')
            GROUP BY week_label
            ORDER BY week_label DESC
            LIMIT 4
        """)
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_ip_detail_any(ip_address: str) -> dict | None:
    """Search ip_results across all sessions, return the most recent match."""
    async with aiosqlite.connect(config.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT ip.* FROM ip_results ip
               JOIN scan_sessions s ON s.id = ip.session_id
               WHERE ip.ip_address=?
               ORDER BY ip.session_id DESC LIMIT 1""",
            (ip_address,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_any_session() -> dict | None:
    """Return most recent session regardless of status."""
    async with aiosqlite.connect(config.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM scan_sessions ORDER BY id DESC LIMIT 1"
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_ip_detail(session_id: int, ip_address: str) -> dict | None:
    async with aiosqlite.connect(config.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM ip_results WHERE session_id=? AND ip_address=?",
            (session_id, ip_address),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


_IP_SORT_WHITELIST = {"abuse_score", "num_reports", "ip_address", "country_code", "scanned_at"}


async def get_ips_paginated(
    session_id: int,
    page: int = 1,
    per_page: int = 50,
    min_score: int | None = None,
    max_score: int | None = None,
    country: str | None = None,
    search_ip: str | None = None,
    sort_by: str = "abuse_score",
    sort_dir: str = "DESC",
) -> tuple[list[dict], int]:
    if sort_by not in _IP_SORT_WHITELIST:
        sort_by = "abuse_score"
    if sort_dir.upper() not in ("ASC", "DESC"):
        sort_dir = "DESC"

    conditions = ["session_id = ?"]
    params: list = [session_id]

    if min_score is not None:
        conditions.append("abuse_score >= ?")
        params.append(min_score)
    if max_score is not None:
        conditions.append("abuse_score <= ?")
        params.append(max_score)
    if country:
        conditions.append("UPPER(country_code) = ?")
        params.append(country.upper())
    if search_ip:
        conditions.append("ip_address LIKE ?")
        params.append(f"%{search_ip}%")

    where = " AND ".join(conditions)

    async with aiosqlite.connect(config.db_path) as db:
        db.row_factory = aiosqlite.Row
        count_cur = await db.execute(
            f"SELECT COUNT(*) FROM ip_results WHERE {where}", params
        )
        total = (await count_cur.fetchone())[0]

        offset = (page - 1) * per_page
        cursor = await db.execute(
            f"SELECT * FROM ip_results WHERE {where} "
            f"ORDER BY {sort_by} {sort_dir} LIMIT ? OFFSET ?",
            params + [per_page, offset],
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows], total


async def get_session_prefix_stats(session_id: int) -> list[dict]:
    async with aiosqlite.connect(config.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM prefix_results WHERE session_id=? ORDER BY max_score DESC",
            (session_id,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def search_ip_across_sessions(ip_address: str, limit: int = 20) -> list[dict]:
    async with aiosqlite.connect(config.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT ir.*, s.started_at AS session_started,
                      s.status AS session_status, s.session_type
               FROM ip_results ir
               JOIN scan_sessions s ON s.id = ir.session_id
               WHERE ir.ip_address = ?
               ORDER BY ir.session_id DESC LIMIT ?""",
            (ip_address, limit),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
