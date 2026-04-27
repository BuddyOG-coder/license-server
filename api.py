import os
from datetime import datetime, timezone, timedelta

from flask import Flask, request, jsonify
from db import get_conn, init_db


APP_SECRET = os.getenv("APP_SECRET")

app = Flask(__name__)
init_db()


@app.get("/")
def home():
    return jsonify({"status": "online"})


def bad_secret():
    return request.headers.get("X-App-Secret") != APP_SECRET


def check_license_common(key, hwid):
    now = datetime.now(timezone.utc)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM licenses WHERE license_key = %s;", (key,))
            lic = cur.fetchone()

            if not lic:
                return False, "invalid_key", None

            if lic["banned"]:
                return False, "banned", lic

            if not lic["active"]:
                return False, "inactive", lic

            if lic["expires_at"] and lic["expires_at"] < now:
                return False, "expired", lic

            if lic["hwid"] and lic["hwid"] != hwid:
                return False, "hwid_mismatch", lic

            if not lic["hwid"]:
                cur.execute("""
                    UPDATE licenses
                    SET hwid = %s, last_check_at = NOW(), last_seen_at = NOW(), online = TRUE
                    WHERE license_key = %s;
                """, (hwid, key))
            else:
                cur.execute("""
                    UPDATE licenses
                    SET last_check_at = NOW(), last_seen_at = NOW(), online = TRUE
                    WHERE license_key = %s;
                """, (key,))

        conn.commit()

    return True, "valid", lic


def ensure_online_columns():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;")
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS online BOOLEAN NOT NULL DEFAULT FALSE;")
        conn.commit()


@app.post("/check")
def check_license():
    if not APP_SECRET:
        return jsonify({"ok": False, "reason": "server_missing_secret"}), 500

    if bad_secret():
        return jsonify({"ok": False, "reason": "bad_secret"}), 401

    ensure_online_columns()

    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip()
    hwid = str(data.get("hwid", "")).strip()

    if not key or not hwid:
        return jsonify({"ok": False, "reason": "missing_key_or_hwid"}), 400

    ok, reason, lic = check_license_common(key, hwid)

    if not ok:
        return jsonify({"ok": False, "reason": reason}), 403

    return jsonify({
        "ok": True,
        "reason": "valid",
        "expires_at": lic["expires_at"].isoformat() if lic and lic["expires_at"] else None
    })


@app.post("/heartbeat")
def heartbeat():
    if not APP_SECRET:
        return jsonify({"ok": False, "reason": "server_missing_secret"}), 500

    if bad_secret():
        return jsonify({"ok": False, "reason": "bad_secret"}), 401

    ensure_online_columns()

    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip()
    hwid = str(data.get("hwid", "")).strip()

    if not key or not hwid:
        return jsonify({"ok": False, "reason": "missing_key_or_hwid"}), 400

    ok, reason, lic = check_license_common(key, hwid)

    if not ok:
        return jsonify({"ok": False, "reason": reason}), 403

    return jsonify({"ok": True, "reason": "heartbeat_ok"})


@app.post("/logout")
def logout():
    if not APP_SECRET:
        return jsonify({"ok": False, "reason": "server_missing_secret"}), 500

    if bad_secret():
        return jsonify({"ok": False, "reason": "bad_secret"}), 401

    ensure_online_columns()

    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip()
    hwid = str(data.get("hwid", "")).strip()

    if not key or not hwid:
        return jsonify({"ok": False, "reason": "missing_key_or_hwid"}), 400

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE licenses
                SET online = FALSE, last_seen_at = NOW()
                WHERE license_key = %s AND hwid = %s;
            """, (key, hwid))
        conn.commit()

    return jsonify({"ok": True, "reason": "logged_out"})


@app.get("/online")
def online_users():
    if not APP_SECRET:
        return jsonify({"ok": False, "reason": "server_missing_secret"}), 500

    if bad_secret():
        return jsonify({"ok": False, "reason": "bad_secret"}), 401

    ensure_online_columns()

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=2)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE licenses
                SET online = FALSE
                WHERE last_seen_at IS NULL OR last_seen_at < %s;
            """, (cutoff,))

            cur.execute("""
                SELECT license_key, hwid, expires_at, last_seen_at, note
                FROM licenses
                WHERE online = TRUE AND last_seen_at >= %s
                ORDER BY last_seen_at DESC;
            """, (cutoff,))

            rows = cur.fetchall()

        conn.commit()

    return jsonify({"ok": True, "online": rows})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
