import os
import secrets
import string
from datetime import datetime, timedelta, timezone

import psycopg2
from psycopg2.extras import RealDictCursor


DATABASE_URL = os.getenv("DATABASE_URL")


def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is missing")
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    id SERIAL PRIMARY KEY,
                    license_key TEXT UNIQUE NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    banned BOOLEAN NOT NULL DEFAULT FALSE,
                    hwid TEXT,
                    expires_at TIMESTAMPTZ,
                    note TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_check_at TIMESTAMPTZ
                );
            """)
        conn.commit()


def generate_key(prefix="DREXX", length=20):
    chars = string.ascii_uppercase + string.digits
    body = "".join(secrets.choice(chars) for _ in range(length))
    return f"{prefix}-{body[:5]}-{body[5:10]}-{body[10:15]}-{body[15:20]}"


def create_license(days=30, note=None):
    key = generate_key()
    expires_at = datetime.now(timezone.utc) + timedelta(days=days)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO licenses (license_key, expires_at, note)
                VALUES (%s, %s, %s)
                RETURNING *;
            """, (key, expires_at, note))
            row = cur.fetchone()
        conn.commit()

    return row