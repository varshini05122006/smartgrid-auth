# app.py - Flask server + smart meter simulator
import hashlib
import secrets
import time

from flask import Flask, jsonify, redirect, render_template, request, url_for

from database import get_conn, init_db, log_event

app = Flask(__name__)
init_db()

SERVER_ID = "UTILITY_SERVER"   # identity the server uses to prove itself
MAX_AGE = 30                   # requests older than 30 s are rejected
OTP_VALIDITY = 60              # OTP is valid for 60 s


def init_details():
    """Extra table that remembers the parameters of every reading attempt
    (created here so database.py does not need to change)."""
    conn = get_conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS reading_details (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        meter_id TEXT, meter_ts REAL, delay REAL, otp TEXT,
        sent_hash TEXT, expected_hash TEXT, status TEXT, created REAL)""")
    conn.commit()
    conn.close()


init_details()


# ---------------------------------------------------------------- helpers
def sha256(text):
    """Return the SHA-256 hex digest of a string."""
    return hashlib.sha256(text.encode()).hexdigest()


def get_key(meter_id):
    """Look up the pre-shared secret key of a meter (None if not registered)."""
    conn = get_conn()
    row = conn.execute("SELECT secret_key FROM meters WHERE meter_id = ?",
                       (meter_id,)).fetchone()
    conn.close()
    return row["secret_key"] if row else None


def is_fresh(ts):
    """Timestamp check: True only if the request is not older than 30 s."""
    try:
        return abs(time.time() - float(ts)) <= MAX_AGE
    except (TypeError, ValueError):
        return False


def reading_hash(meter_id, kwh, voltage, ts, otp, key):
    """Integrity hash of a reading. Contains the secret key, so an attacker
    who changes the values cannot compute a matching hash."""
    return sha256(f"{meter_id}|{float(kwh):.2f}|{float(voltage):.2f}|{ts}|{otp}|{key}")


def reply(status, message, code=200, **extra):
    """Build a JSON reply that always has 'status' and 'message'."""
    body = {"status": status, "message": message}
    body.update(extra)
    return jsonify(body), code


def save_detail(meter_id, d, status, expected=None):
    """Store the parameters of a reading attempt for the dashboard."""
    try:
        ts = float(d.get("timestamp"))
        delay = round(time.time() - ts, 3)
    except (TypeError, ValueError):
        ts, delay = None, None
    conn = get_conn()
    conn.execute(
        "INSERT INTO reading_details (meter_id, meter_ts, delay, otp, sent_hash, "
        "expected_hash, status, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (meter_id, ts, delay, str(d.get("otp")), str(d.get("data_hash")),
         expected, status, time.time()))
    conn.commit()
    conn.close()


@app.template_filter("ts")
def fmt_ts(value):
    """Show a Unix time as 'dd Mon HH:MM:SS'."""
    try:
        return time.strftime("%d %b %H:%M:%S", time.localtime(float(value)))
    except (TypeError, ValueError):
        return "-"


# ---------------------------------------------------------- SERVER API
@app.route("/api/challenge", methods=["POST"])
def api_challenge():
    """Step 1: meter asks to start; server sends a random nonce."""
    data = request.get_json(silent=True) or {}
    meter_id = data.get("meter_id")

    if get_key(meter_id) is None:
        log_event(meter_id, "failed", "Unknown meter ID")
        return reply("failed", "Unknown meter", 401)
    if not is_fresh(data.get("timestamp")):
        log_event(meter_id, "replay", "Old timestamp on challenge request")
        return reply("replay", "Request older than 30 s", 400)

    nonce = secrets.token_hex(8)            # random challenge
    conn = get_conn()
    conn.execute("INSERT INTO nonces (nonce, meter_id, created) VALUES (?, ?, ?)",
                 (nonce, meter_id, time.time()))
    conn.commit()
    conn.close()
    return reply("ok", "Challenge issued", nonce=nonce)


@app.route("/api/authenticate", methods=["POST"])
def api_authenticate():
    """Step 2: meter answers the challenge; server verifies and proves itself."""
    data = request.get_json(silent=True) or {}
    meter_id = data.get("meter_id")
    nonce = data.get("nonce")
    key = get_key(meter_id)

    if key is None:
        log_event(meter_id, "failed", "Unknown meter ID")
        return reply("failed", "Unknown meter", 401)
    if not is_fresh(data.get("timestamp")):
        log_event(meter_id, "replay", "Old timestamp on authenticate request")
        return reply("replay", "Request older than 30 s", 400)

    conn = get_conn()
    row = conn.execute("SELECT * FROM nonces WHERE nonce = ? AND meter_id = ?",
                       (nonce, meter_id)).fetchone()
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

    # Burn the nonce immediately so it can never be used again
    conn.execute("UPDATE nonces SET used = 1 WHERE nonce = ?", (nonce,))
    conn.commit()

    # Verify the meter: SHA-256(meter ID + secret key + nonce)
    expected = sha256(meter_id + key + nonce)
    if not secrets.compare_digest(expected, str(data.get("meter_proof"))):
        conn.close()
        log_event(meter_id, "failed", "Wrong key - meter proof did not match")
        return reply("failed", "Meter proof invalid (wrong key)", 401)

    # Server proves itself: SHA-256(server ID + secret key + meter's nonce)
    server_proof = sha256(SERVER_ID + key + str(data.get("meter_nonce")))

    # Generate a 6-digit OTP, valid 60 s, one use
    otp = f"{secrets.randbelow(1000000):06d}"
    conn.execute("INSERT INTO otps (meter_id, otp, created) VALUES (?, ?, ?)",
                 (meter_id, otp, time.time()))
    conn.commit()
    conn.close()

    log_event(meter_id, "success", "Mutual authentication OK, OTP issued")
    # NOTE: in a real grid the OTP goes over a separate secure channel (SMS/HAN).
    return reply("success", "Meter authenticated", server_proof=server_proof, otp=otp)


@app.route("/api/reading", methods=["POST"])
def api_reading():
    """Step 3: meter sends reading + OTP + integrity hash."""
    d = request.get_json(silent=True) or {}
    meter_id = d.get("meter_id")
    key = get_key(meter_id)

    if key is None:
        log_event(meter_id, "failed", "Unknown meter ID")
        return reply("failed", "Unknown meter", 401)

    # 1) Timestamp check
    if not is_fresh(d.get("timestamp")):
        log_event(meter_id, "replay", "Reading older than 30 s")
        save_detail(meter_id, d, "replay")
        return reply("replay", "Reading older than 30 s - replay attack", 400)

    # 2) OTP check (exists, unused, not expired)
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM otps WHERE meter_id = ? AND otp = ? ORDER BY id DESC LIMIT 1",
        (meter_id, str(d.get("otp")))).fetchone()
    if row is None:
        conn.close()
        log_event(meter_id, "failed", "Invalid OTP")
        save_detail(meter_id, d, "failed")
        return reply("failed", "Invalid OTP", 401)
    if row["used"]:
        conn.close()
        log_event(meter_id, "replay", "OTP already used")
        save_detail(meter_id, d, "replay")
        return reply("replay", "OTP already used - replay attack", 401)
    if time.time() - row["created"] > OTP_VALIDITY:
        conn.close()
        log_event(meter_id, "failed", "OTP expired (60 s)")
        save_detail(meter_id, d, "failed")
        return reply("failed", "OTP expired", 401)

    # Mark the OTP as used (one-time)
    conn.execute("UPDATE otps SET used = 1 WHERE id = ?", (row["id"],))
    conn.commit()

    # 3) Integrity check: recompute the hash and compare
    try:
        expected = reading_hash(meter_id, d["kwh"], d["voltage"],
                                d["timestamp"], d["otp"], key)
    except (KeyError, TypeError, ValueError):
        conn.close()
        log_event(meter_id, "failed", "Malformed reading")
        save_detail(meter_id, d, "failed")
        return reply("failed", "Malformed reading", 400)

    if not secrets.compare_digest(expected, str(d.get("data_hash"))):
        conn.close()
        log_event(meter_id, "tampered", "Hash mismatch - data changed in transit")
        save_detail(meter_id, d, "tampered", expected)
        return reply("tampered", "Hash mismatch - data tampered", 400)

    # All checks passed: store the reading
    conn.execute(
        "INSERT INTO readings (meter_id, kwh, voltage, received_at) VALUES (?, ?, ?, ?)",
        (meter_id, float(d["kwh"]), float(d["voltage"]), time.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    log_event(meter_id, "success", "Reading accepted")
    save_detail(meter_id, d, "success", expected)
    return reply("success", "Reading accepted")


# ------------------------------------------------------- METER SIMULATOR
def meter_authenticate(client, meter_id, key):
    """Meter side of mutual authentication. Returns (otp, message)."""
    # Ask for a challenge
    r = client.post("/api/challenge", json={"meter_id": meter_id, "timestamp": time.time()})
    body = r.get_json()
    if r.status_code != 200:
        return None, f"{body['status'].upper()}: {body['message']}"
    nonce = body["nonce"]

    # Answer it, and send our own nonce so the server can prove itself
    meter_nonce = secrets.token_hex(8)
    r = client.post("/api/authenticate", json={
        "meter_id": meter_id,
        "nonce": nonce,
        "meter_nonce": meter_nonce,
        "meter_proof": sha256(meter_id + key + nonce),
        "timestamp": time.time(),
    })
    body = r.get_json()
    if r.status_code != 200:
        return None, f"{body['status'].upper()}: {body['message']}"

    # Meter verifies the SERVER (second half of mutual authentication)
    if body["server_proof"] != sha256(SERVER_ID + key + meter_nonce):
        return None, "Meter rejected the server (fake server)"
    return body["otp"], "Mutual authentication OK"


def make_packet(meter_id, key, otp):
    """Build a reading packet with kWh, voltage, timestamp and integrity hash."""
    kwh = round(100 + secrets.randbelow(9000) / 10, 2)
    voltage = round(220 + secrets.randbelow(200) / 10, 2)
    ts = time.time()
    return {"meter_id": meter_id, "kwh": kwh, "voltage": voltage,
            "timestamp": ts, "otp": otp,
            "data_hash": reading_hash(meter_id, kwh, voltage, ts, otp, key)}


def send_packet(client, packet):
    body = client.post("/api/reading", json=packet).get_json()
    return f"{body['status'].upper()}: {body['message']}"


@app.route("/simulate/<attack>", methods=["POST"])
def simulate(attack):
    """Dashboard buttons call this: normal run or one of the 3 attacks."""
    meter_id = request.form["meter_id"]
    real_key = get_key(meter_id)
    client = app.test_client()          # lets the 'meter' call the API above

    if attack == "wrong_key":
        # Attacker does not know the secret key
        otp, msg = meter_authenticate(client, meter_id, "wrong-key-123")
        result = f"Wrong key attack on {meter_id} -> {msg}"

    else:
        otp, msg = meter_authenticate(client, meter_id, real_key)
        if otp is None:
            result = f"{meter_id} -> {msg}"
        else:
            packet = make_packet(meter_id, real_key, otp)
            if attack == "tampered":
                packet["kwh"] = packet["kwh"] + 500      # change data, keep old hash
                result = f"Tampered data on {meter_id} -> {send_packet(client, packet)}"
            elif attack == "replay":
                first = send_packet(client, packet)       # genuine message
                second = send_packet(client, packet)      # attacker resends it
                result = f"Replay on {meter_id} -> first: {first} | resent: {second}"
            else:
                result = f"Normal session on {meter_id} -> {send_packet(client, packet)}"

    return redirect(url_for("index", msg=result))


# ------------------------------------------------------------ CLEAR DATA
@app.route("/clear", methods=["POST"])
def clear_records():
    """Delete all generated records (meters are kept)."""
    tables = ["readings", "auth_log", "otps", "nonces", "reading_details"]
    conn = get_conn()
    for t in tables:
        conn.execute(f"DELETE FROM {t}")
    try:   # restart the # numbering from 1
        conn.execute("DELETE FROM sqlite_sequence WHERE name IN (%s)" %
                     ",".join("?" * len(tables)), tables)
    except Exception:
        pass
    conn.commit()
    conn.close()
    return redirect(url_for("index", msg="All records cleared (registered meters kept)."))


# -------------------------------------------------------------- DASHBOARD
@app.route("/")
def index():
    conn = get_conn()
    meters = conn.execute("SELECT * FROM meters").fetchall()
    readings = conn.execute("SELECT * FROM readings ORDER BY id DESC LIMIT 10").fetchall()
    logs = conn.execute("SELECT * FROM auth_log ORDER BY id DESC LIMIT 20").fetchall()
    details = conn.execute("SELECT * FROM reading_details ORDER BY id DESC LIMIT 10").fetchall()
    otps = conn.execute("SELECT * FROM otps ORDER BY id DESC LIMIT 8").fetchall()
    nonces = conn.execute("SELECT * FROM nonces ORDER BY created DESC LIMIT 8").fetchall()
    counts = {r["status"]: r["c"] for r in conn.execute(
        "SELECT status, COUNT(*) AS c FROM auth_log GROUP BY status").fetchall()}
    conn.close()

    stats = {"total": sum(counts.values()),
             "success": counts.get("success", 0),
             "failed": counts.get("failed", 0),
             "replay": counts.get("replay", 0),
             "tampered": counts.get("tampered", 0)}
    params = [("Hash algorithm", "SHA-256"),
              ("Timestamp window", f"{MAX_AGE} s"),
              ("OTP validity", f"{OTP_VALIDITY} s (one use)"),
              ("OTP length", "6 digits"),
              ("Nonce", "64-bit random, one use"),
              ("Server ID", SERVER_ID)]
    return render_template("index.html", meters=meters, readings=readings, logs=logs,
                           details=details, otps=otps, nonces=nonces, stats=stats,
                           params=params, msg=request.args.get("msg"))


if __name__ == "__main__":
    app.run(debug=True)