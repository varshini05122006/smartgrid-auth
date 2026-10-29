# app.py - Flask server + smart meter simulator (SHA-512)
import hashlib
import secrets
import time

from flask import Flask, jsonify, redirect, render_template, request, url_for
from database import get_conn, init_db, log_event

app = Flask(__name__)
init_db()

SERVER_ID = "UTILITY_SERVER"
MAX_AGE = 30
OTP_VALIDITY = 60


def init_details():
    """Create the table used to show reading/hash checks on the dashboard."""
    conn = get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS reading_details (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meter_id TEXT,
            meter_ts REAL,
            delay REAL,
            otp TEXT,
            sent_hash TEXT,
            expected_hash TEXT,
            status TEXT,
            created REAL
        )
        """
    )
    conn.commit()
    conn.close()


init_details()


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
def sha512(text):
    """Return the SHA-512 hexadecimal digest (128 hexadecimal characters)."""
    return hashlib.sha512(str(text).encode("utf-8")).hexdigest()


def get_key(meter_id):
    """Return a registered meter's pre-shared secret key, or None."""
    if not meter_id:
        return None
    conn = get_conn()
    row = conn.execute(
        "SELECT secret_key FROM meters WHERE meter_id = ?", (meter_id,)
    ).fetchone()
    conn.close()
    return row["secret_key"] if row else None


def is_fresh(ts):
    """Accept timestamps within MAX_AGE seconds of the current time."""
    try:
        return abs(time.time() - float(ts)) <= MAX_AGE
    except (TypeError, ValueError):
        return False


def reading_hash(meter_id, kwh, voltage, ts, otp, key):
    """Hash the reading fields using SHA-512."""
    message = (
        f"{meter_id}|{float(kwh):.2f}|{float(voltage):.2f}|"
        f"{ts}|{otp}|{key}"
    )
    return sha512(message)


def reply(status, message, code=200, **extra):
    """Build a JSON response with consistent status and message fields."""
    body = {"status": status, "message": message}
    body.update(extra)
    return jsonify(body), code


def save_detail(meter_id, data, status, expected=None):
    """Save details of a reading attempt for the dashboard."""
    try:
        ts = float(data.get("timestamp"))
        delay = round(time.time() - ts, 3)
    except (TypeError, ValueError):
        ts, delay = None, None

    conn = get_conn()
    conn.execute(
        """
        INSERT INTO reading_details
            (meter_id, meter_ts, delay, otp, sent_hash, expected_hash,
             status, created)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            meter_id,
            ts,
            delay,
            str(data.get("otp")),
            str(data.get("data_hash")),
            expected,
            status,
            time.time(),
        ),
    )
    conn.commit()
    conn.close()


@app.template_filter("ts")
def fmt_ts(value):
    """Format a Unix timestamp for display in the dashboard."""
    try:
        return time.strftime("%d %b %H:%M:%S", time.localtime(float(value)))
    except (TypeError, ValueError):
        return "-"


# ---------------------------------------------------------------------
# Server API: challenge, mutual authentication, and reading verification
# ---------------------------------------------------------------------
@app.route("/api/challenge", methods=["POST"])
def api_challenge():
    """Step 1: issue a random nonce to a registered meter."""
    data = request.get_json(silent=True) or {}
    meter_id = data.get("meter_id")

    if get_key(meter_id) is None:
        log_event(meter_id, "failed", "Unknown meter ID")
        return reply("failed", "Unknown meter", 401)

    if not is_fresh(data.get("timestamp")):
        log_event(meter_id, "replay", "Old timestamp on challenge request")
        return reply("replay", "Request older than 30 seconds", 400)

    nonce = secrets.token_hex(8)
    conn = get_conn()
    conn.execute(
        "INSERT INTO nonces (nonce, meter_id, created) VALUES (?, ?, ?)",
        (nonce, meter_id, time.time()),
    )
    conn.commit()
    conn.close()
    return reply("ok", "Challenge issued", nonce=nonce)


@app.route("/api/authenticate", methods=["POST"])
def api_authenticate():
    """Step 2: verify the meter and return the server proof plus a one-time OTP."""
    data = request.get_json(silent=True) or {}
    meter_id = data.get("meter_id")
    nonce = data.get("nonce")
    key = get_key(meter_id)

    if key is None:
        log_event(meter_id, "failed", "Unknown meter ID")
        return reply("failed", "Unknown meter", 401)

    if not is_fresh(data.get("timestamp")):
        log_event(meter_id, "replay", "Old timestamp on authenticate request")
        return reply("replay", "Request older than 30 seconds", 400)

    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM nonces WHERE nonce = ? AND meter_id = ?",
        (nonce, meter_id),
    ).fetchone()

    if row is None:
        conn.close()
        log_event(meter_id, "failed", "Nonce was never issued")
        return reply("failed", "Unknown nonce", 401)

    if row["used"]:
        conn.close()
        log_event(meter_id, "replay", "Nonce already used")
        return reply("replay", "Nonce already used - replay attack", 401)

    if time.time() - row["created"] > MAX_AGE:
        conn.close()
        log_event(meter_id, "failed", "Nonce expired")
        return reply("failed", "Nonce expired", 401)

    # Burn the nonce before verifying the proof so it cannot be reused.
    conn.execute("UPDATE nonces SET used = 1 WHERE nonce = ?", (nonce,))
    conn.commit()

    # Meter proof: SHA-512(meter ID + shared key + server nonce).
    expected = sha512(meter_id + key + nonce)
    if not secrets.compare_digest(expected, str(data.get("meter_proof", ""))):
        conn.close()
        log_event(meter_id, "failed", "Wrong key - meter proof did not match")
        return reply("failed", "Meter proof invalid (wrong key)", 401)

    # Server proof: SHA-512(server ID + shared key + meter nonce).
    meter_nonce = str(data.get("meter_nonce", ""))
    server_proof = sha512(SERVER_ID + key + meter_nonce)

    # Generate a six-digit OTP. It expires and can be used only once.
    otp = f"{secrets.randbelow(1_000_000):06d}"
    conn.execute(
        "INSERT INTO otps (meter_id, otp, created) VALUES (?, ?, ?)",
        (meter_id, otp, time.time()),
    )
    conn.commit()
    conn.close()

    log_event(meter_id, "success", "Mutual authentication OK, OTP issued")
    return reply(
        "success",
        "Meter authenticated",
        server_proof=server_proof,
        otp=otp,
    )


@app.route("/api/reading", methods=["POST"])
def api_reading():
    """Step 3: validate the timestamp, one-time OTP, and SHA-512 integrity hash."""
    data = request.get_json(silent=True) or {}
    meter_id = data.get("meter_id")
    key = get_key(meter_id)

    if key is None:
        log_event(meter_id, "failed", "Unknown meter ID")
        return reply("failed", "Unknown meter", 401)

    # 1. Timestamp freshness.
    if not is_fresh(data.get("timestamp")):
        log_event(meter_id, "replay", "Reading older than 30 seconds")
        save_detail(meter_id, data, "replay")
        return reply("replay", "Reading older than 30 seconds - replay attack", 400)

    # 2. OTP must exist, be unused, and not be expired.
    conn = get_conn()
    row = conn.execute(
        """
        SELECT * FROM otps
        WHERE meter_id = ? AND otp = ?
        ORDER BY id DESC LIMIT 1
        """,
        (meter_id, str(data.get("otp"))),
    ).fetchone()

    if row is None:
        conn.close()
        log_event(meter_id, "failed", "Invalid OTP")
        save_detail(meter_id, data, "failed")
        return reply("failed", "Invalid OTP", 401)

    if row["used"]:
        conn.close()
        log_event(meter_id, "replay", "OTP already used")
        save_detail(meter_id, data, "replay")
        return reply("replay", "OTP already used - replay attack", 401)

    if time.time() - row["created"] > OTP_VALIDITY:
        conn.close()
        log_event(meter_id, "failed", "OTP expired")
        save_detail(meter_id, data, "failed")
        return reply("failed", "OTP expired", 401)

    # Mark the OTP used, including when the subsequent integrity check fails.
    conn.execute("UPDATE otps SET used = 1 WHERE id = ?", (row["id"],))
    conn.commit()

    # 3. Recompute the SHA-512 integrity hash.
    try:
        expected = reading_hash(
            meter_id,
            data["kwh"],
            data["voltage"],
            data["timestamp"],
            data["otp"],
            key,
        )
    except (KeyError, TypeError, ValueError):
        conn.close()
        log_event(meter_id, "failed", "Malformed reading")
        save_detail(meter_id, data, "failed")
        return reply("failed", "Malformed reading", 400)

    if not secrets.compare_digest(expected, str(data.get("data_hash", ""))):
        conn.close()
        log_event(meter_id, "tampered", "Hash mismatch - data changed in transit")
        save_detail(meter_id, data, "tampered", expected)
        return reply("tampered", "Hash mismatch - data tampered", 400)

    # All checks passed: store the reading.
    try:
        kwh = float(data["kwh"])
        voltage = float(data["voltage"])
    except (KeyError, TypeError, ValueError):
        conn.close()
        log_event(meter_id, "failed", "Malformed reading")
        save_detail(meter_id, data, "failed")
        return reply("failed", "Malformed reading", 400)

    conn.execute(
        """
        INSERT INTO readings (meter_id, kwh, voltage, received_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            meter_id,
            kwh,
            voltage,
            time.strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()
    conn.close()
    log_event(meter_id, "success", "Reading accepted")
    save_detail(meter_id, data, "success", expected)
    return reply("success", "Reading accepted")


# ---------------------------------------------------------------------
# Smart meter simulator
# ---------------------------------------------------------------------
def meter_authenticate(client, meter_id, key):
    """Simulate the meter side of mutual authentication."""
    response = client.post(
        "/api/challenge",
        json={"meter_id": meter_id, "timestamp": time.time()},
    )
    body = response.get_json() or {}

    if response.status_code != 200:
        return None, f"{body.get('status', 'ERROR').upper()}: {body.get('message', 'Request failed')}"

    nonce = body["nonce"]
    meter_nonce = secrets.token_hex(8)

    response = client.post(
        "/api/authenticate",
        json={
            "meter_id": meter_id,
            "nonce": nonce,
            "meter_nonce": meter_nonce,
            "meter_proof": sha512(meter_id + key + nonce),
            "timestamp": time.time(),
        },
    )
    body = response.get_json() or {}

    if response.status_code != 200:
        return None, f"{body.get('status', 'ERROR').upper()}: {body.get('message', 'Request failed')}"

    # Verify the server's proof using the same SHA-512 construction.
    expected_server_proof = sha512(SERVER_ID + key + meter_nonce)
    if not secrets.compare_digest(
        str(body.get("server_proof", "")), expected_server_proof
    ):
        return None, "Meter rejected the server (fake server)"

    return body["otp"], "Mutual authentication OK"


def make_packet(meter_id, key, otp):
    """Create a reading packet and its SHA-512 integrity hash."""
    kwh = round(100 + secrets.randbelow(9000) / 10, 2)
    voltage = round(220 + secrets.randbelow(200) / 10, 2)
    timestamp = time.time()

    return {
        "meter_id": meter_id,
        "kwh": kwh,
        "voltage": voltage,
        "timestamp": timestamp,
        "otp": otp,
        "data_hash": reading_hash(
            meter_id, kwh, voltage, timestamp, otp, key
        ),
    }


def send_packet(client, packet):
    response = client.post("/api/reading", json=packet)
    body = response.get_json() or {}
    return f"{body.get('status', 'ERROR').upper()}: {body.get('message', 'Request failed')}"


@app.route("/simulate/<attack>", methods=["POST"])
def simulate(attack):
    """Run a normal session or demonstrate one of the attack scenarios."""
    if attack not in {"normal", "wrong_key", "tampered", "replay"}:
        return redirect(url_for("index", msg="Unknown simulation type"))

    meter_id = request.form.get("meter_id", "")
    real_key = get_key(meter_id)
    if real_key is None:
        return redirect(url_for("index", msg="Select a registered meter"))

    client = app.test_client()

    if attack == "wrong_key":
        _, message = meter_authenticate(client, meter_id, "wrong-key-123")
        result = f"Wrong key attack on {meter_id} -> {message}"
        return redirect(url_for("index", msg=result))

    otp, message = meter_authenticate(client, meter_id, real_key)
    if otp is None:
        return redirect(url_for("index", msg=f"{meter_id} -> {message}"))

    packet = make_packet(meter_id, real_key, otp)

    if attack == "tampered":
        packet["kwh"] = packet["kwh"] + 500  # Change data but keep old hash.
        result = f"Tampered data on {meter_id} -> {send_packet(client, packet)}"
    elif attack == "replay":
        first = send_packet(client, packet)
        second = send_packet(client, packet)
        result = f"Replay on {meter_id} -> first: {first} | resent: {second}"
    else:
        result = f"Normal session on {meter_id} -> {send_packet(client, packet)}"

    return redirect(url_for("index", msg=result))


# ---------------------------------------------------------------------
# Clear generated data and render the dashboard
# ---------------------------------------------------------------------
@app.route("/clear", methods=["POST"])
def clear_records():
    """Delete generated records while keeping registered meters."""
    tables = ["readings", "auth_log", "otps", "nonces", "reading_details"]
    conn = get_conn()

    for table in tables:
        conn.execute(f"DELETE FROM {table}")

    try:
        conn.execute(
            "DELETE FROM sqlite_sequence WHERE name IN (%s)"
            % ",".join("?" * len(tables)),
            tables,
        )
    except Exception:
        # sqlite_sequence may not exist if no AUTOINCREMENT table was created.
        pass

    conn.commit()
    conn.close()
    return redirect(
        url_for("index", msg="All records cleared (registered meters kept).")
    )


@app.route("/")
def index():
    conn = get_conn()
    meters = conn.execute("SELECT * FROM meters").fetchall()
    readings = conn.execute(
        "SELECT * FROM readings ORDER BY id DESC LIMIT 10"
    ).fetchall()
    logs = conn.execute(
        "SELECT * FROM auth_log ORDER BY id DESC LIMIT 20"
    ).fetchall()
    details = conn.execute(
        "SELECT * FROM reading_details ORDER BY id DESC LIMIT 10"
    ).fetchall()
    otps = conn.execute(
        "SELECT * FROM otps ORDER BY id DESC LIMIT 8"
    ).fetchall()
    nonces = conn.execute(
        "SELECT * FROM nonces ORDER BY created DESC LIMIT 8"
    ).fetchall()

    counts = {
        row["status"]: row["c"]
        for row in conn.execute(
            "SELECT status, COUNT(*) AS c FROM auth_log GROUP BY status"
        ).fetchall()
    }
    conn.close()

    stats = {
        "total": sum(counts.values()),
        "success": counts.get("success", 0),
        "failed": counts.get("failed", 0),
        "replay": counts.get("replay", 0),
        "tampered": counts.get("tampered", 0),
    }
    params = [
        ("Hash algorithm", "SHA-512"),
        ("Timestamp window", f"{MAX_AGE} s"),
        ("OTP validity", f"{OTP_VALIDITY} s (one use)"),
        ("OTP length", "6 digits"),
        ("Nonce", "64-bit random, one use"),
        ("Server ID", SERVER_ID),
    ]

    return render_template(
        "index.html",
        meters=meters,
        readings=readings,
        logs=logs,
        details=details,
        otps=otps,
        nonces=nonces,
        stats=stats,
        params=params,
        msg=request.args.get("msg"),
    )


if __name__ == "__main__":
    app.run(debug=True)
