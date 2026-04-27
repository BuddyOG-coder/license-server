import os
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from db import get_conn, init_db


APP_SECRET = os.getenv("APP_SECRET")

app = Flask(__name__)
init_db()


@app.get("/")
def home():
    return jsonify({"status": "online"})


@app.post("/check")
def check_license():
    if not APP_SECRET:
        return jsonify({"ok": False, "reason": "server_missing_secret"}), 500

    if request.headers.get("X-App-Secret") != APP_SECRET:
        return jsonify({"ok": False, "reason": "bad_secret"}), 401

    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip()
    hwid = str(data.get("hwid", "")).strip()

    if not key or not hwid:
        return jsonify({"ok": False, "reason": "missing_key_or_hwid"}), 400

    now = datetime.now(timezone.utc)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM licenses WHERE license_key = %s;", (key,))
            lic = cur.fetchone()

            if not lic:
                return jsonify({"ok": False, "reason": "invalid_key"}), 403

            if lic["banned"]:
                return jsonify({"ok": False, "reason": "banned"}), 403

            if not lic["active"]:
                return jsonify({"ok": False, "reason": "inactive"}), 403

            if lic["expires_at"] and lic["expires_at"] < now:
                return jsonify({"ok": False, "reason": "expired"}), 403

            if lic["hwid"] and lic["hwid"] != hwid:
                return jsonify({"ok": False, "reason": "hwid_mismatch"}), 403

            if not lic["hwid"]:
                cur.execute("""
                    UPDATE licenses
                    SET hwid = %s, last_check_at = NOW()
                    WHERE license_key = %s;
                """, (hwid, key))
            else:
                cur.execute("""
                    UPDATE licenses
                    SET last_check_at = NOW()
                    WHERE license_key = %s;
                """, (key,))

        conn.commit()

    return jsonify({
        "ok": True,
        "reason": "valid",
        "expires_at": lic["expires_at"].isoformat() if lic["expires_at"] else None
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
