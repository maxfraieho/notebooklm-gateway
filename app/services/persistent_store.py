import os
import json
import logging
from typing import Optional

import psycopg2
from psycopg2.extras import DictCursor

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "")


def _get_conn():
    return psycopg2.connect(DATABASE_URL)


def init_db():
    if not DATABASE_URL:
        logger.warning("DATABASE_URL not set, persistent storage disabled")
        return False
    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS kv_store (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
        conn.commit()
        conn.close()
        logger.info("Persistent store initialized (kv_store table ready)")
        return True
    except Exception as e:
        logger.error(f"Failed to init persistent store: {e}")
        return False


def put(key: str, value: str) -> bool:
    if not DATABASE_URL:
        return False
    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO kv_store (key, value, updated_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
            """, (key, value))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Failed to store key={key}: {e}")
        return False


def get(key: str) -> Optional[str]:
    if not DATABASE_URL:
        return None
    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT value FROM kv_store WHERE key = %s", (key,))
            row = cur.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception as e:
        logger.error(f"Failed to get key={key}: {e}")
        return None


def delete(key: str) -> bool:
    if not DATABASE_URL:
        return False
    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM kv_store WHERE key = %s", (key,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Failed to delete key={key}: {e}")
        return False


def put_json(key: str, data: dict) -> bool:
    return put(key, json.dumps(data))


def get_json(key: str) -> Optional[dict]:
    val = get(key)
    if val is None:
        return None
    try:
        return json.loads(val)
    except json.JSONDecodeError:
        return None
