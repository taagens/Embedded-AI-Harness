"""
MQTT Controller — manages a mosquitto broker for ESP32 MQTT client testing.

Used by the portal to start/stop a local MQTT broker accessible to devices
on the testbench WiFi AP. Open (anonymous) by default; started with a username
and password it refuses anonymous clients and accepts only that account, so a
DUT's MQTT authentication can be tested (FR-029).
"""

import logging
import os
import re
import subprocess
import threading
import time

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MQTT_PORT = 1883
WORK_DIR = "/tmp/mqtt-tester"
MOSQUITTO_CONF = os.path.join(WORK_DIR, "mosquitto.conf")
MOSQUITTO_LOG = os.path.join(WORK_DIR, "mosquitto.log")
PASSWORD_FILE = os.path.join(WORK_DIR, "passwd")
MAX_CREDENTIAL_LEN = 64
SUBSCRIPTION_LOG_TAIL = 8 * 1024 * 1024   # bytes of the broker log read per query

# ---------------------------------------------------------------------------
# Module state
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_active = False
_proc = None
_auth_user = None   # username the running broker requires, or None when open


# ---------------------------------------------------------------------------
# Pure helpers (host-tested: pytest/host/test_mqtt_controller.py)
# ---------------------------------------------------------------------------

def config_lines(port, log_path, password_file=None):
    """mosquitto.conf lines: open broker, or password-only when a file is given."""
    lines = [f"listener {port}"]
    if password_file:
        lines += ["allow_anonymous false", f"password_file {password_file}"]
    else:
        lines.append("allow_anonymous true")
    return lines + [f"log_dest file {log_path}", "log_type all"]


_CONNECT_RE = re.compile(r"New client connected from (\S+?):\d+ as (\S+) \(")
_SUB_TOPIC_RE = re.compile(r"\t(.+) \(QoS (\d)\)$")


def parse_subscriptions(lines, since=0.0, address=None):
    """SUBSCRIBE records in a mosquitto log written with `log_type all` (FR-041).

    Mosquitto logs a SUBSCRIBE as `<epoch>: Received SUBSCRIBE from <client>`
    followed by one `<epoch>: \\t<filter> (QoS <n>)` line per topic filter. The
    client's address comes from its latest `New client connected from <ip>:<port>
    as <client> (...)` line. Returns `[{ts, client, address, topic, qos}]` in log
    order, keeping records at or after `since` and, when given, from `address`.

    Only these fields leave the log: the connect line can also name the MQTT
    username, and no other part of the log is returned.
    """
    clients, out, cur = {}, [], None
    for raw in lines:
        head, sep, msg = raw.rstrip("\r\n").partition(": ")
        if not sep:
            continue
        try:
            ts = float(head)
        except ValueError:
            continue
        m = _CONNECT_RE.match(msg)
        if m:
            clients[m.group(2)] = m.group(1).strip("[]")
            cur = None
            continue
        if msg.startswith("Received SUBSCRIBE from "):
            cur = msg[len("Received SUBSCRIBE from "):].strip()
            continue
        if msg.startswith("Received ") or msg.startswith("Sending SUBACK"):
            cur = None
            continue
        t = _SUB_TOPIC_RE.match(msg)
        if t and cur is not None:
            rec = {"ts": ts, "client": cur, "address": clients.get(cur),
                   "topic": t.group(1), "qos": int(t.group(2))}
            if ts >= since and (address is None or rec["address"] == address):
                out.append(rec)
    return out


def validate_credentials(username, password):
    """Raise ValueError unless both fit one `user:hash` line of a password file."""
    for name, value in (("username", username), ("password", password)):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{name} must be a non-empty string")
        if len(value) > MAX_CREDENTIAL_LEN:
            raise ValueError(f"{name} longer than {MAX_CREDENTIAL_LEN} characters")
        if any(c in value for c in "\r\n\0"):
            raise ValueError(f"{name} contains a line break or NUL")
    if ":" in username:
        raise ValueError("username must not contain ':'")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def broker_user(name="mosquitto"):
    """(uid, gid) mosquitto drops privileges to when started as root, or None."""
    try:
        import pwd
        pw = pwd.getpwnam(name)
        return pw.pw_uid, pw.pw_gid
    except (ImportError, KeyError):
        return None


def _write_password_file(username, password):
    """Create PASSWORD_FILE (0600) holding one hashed account."""
    if os.path.exists(PASSWORD_FILE):
        os.remove(PASSWORD_FILE)
    fd = os.open(PASSWORD_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    # -b takes the password on the command line: visible to local users of the
    # Pi for the moment the hash is computed. Acceptable for throw-away test
    # credentials; never pass a real password here.
    r = subprocess.run(["mosquitto_passwd", "-b", PASSWORD_FILE, username, password],
                       capture_output=True, timeout=15, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"mosquitto_passwd failed: {r.stderr.decode(errors='replace')[:200]}")
    # Started as root, mosquitto drops to its own user before it opens the
    # password file; a 0600 root-owned file is then unreadable ("Unable to open
    # pwfile", seen on the bench 2026-11-18). Hand the file to that user.
    owner = broker_user() if os.geteuid() == 0 else None
    if owner:
        os.chown(PASSWORD_FILE, owner[0], owner[1])


def _ensure_work_dir():
    os.makedirs(WORK_DIR, exist_ok=True)


def _kill_proc(proc, timeout=5.0):
    """Terminate a subprocess, SIGKILL if it won't die."""
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
    except OSError:
        return
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass


def _kill_existing():
    """Kill a previously-started *test* broker, and only that (best effort).

    The pattern is matched against our own config path, not the bare word
    "mosquitto". A broad `pkill -f mosquitto` also kills a system
    `mosquitto.service` or any other broker on the host — a test fixture must
    never take down infrastructure it does not own.

    This reclaims the port after a portal restart, where the old broker is still
    running but `_proc` no longer refers to it.
    """
    try:
        subprocess.run(
            ["pkill", "-f", f"mosquitto -c {MOSQUITTO_CONF}"],
            capture_output=True, timeout=5, check=False,
        )
        time.sleep(0.3)
    except Exception:
        pass


def _port_owner() -> str:
    """Describe what is listening on MQTT_PORT, or '' if nothing is."""
    try:
        out = subprocess.run(
            ["ss", "-tlnp", f"sport = :{MQTT_PORT}"],
            capture_output=True, timeout=5, check=False,
        ).stdout.decode(errors="replace")
    except Exception:
        return ""
    lines = [ln for ln in out.splitlines()[1:] if ln.strip()]
    return lines[0].strip() if lines else ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start(username=None, password=None):
    """Start the mosquitto MQTT broker. Returns dict with port and auth.

    With `username` and `password` the broker refuses anonymous clients and
    accepts only that account; without them it is open. Asking for a different
    mode (or account) than the running broker has restarts it — retained
    messages do not survive that.
    """
    global _active, _proc, _auth_user

    if username is not None or password is not None:
        validate_credentials(username, password)
    with _lock:
        running = _active and _proc is not None and _proc.poll() is None
        if running and username is None and _auth_user is None:
            return {"port": MQTT_PORT, "auth": False}
        if running:
            # an auth broker is always restarted: the password may have changed
            _kill_proc(_proc)
            _proc = None
            _active = False

        _ensure_work_dir()
        _kill_existing()

        # If something still holds the port it is not ours, so refuse rather than
        # kill it. Silently killing a broker we did not start is how a test run
        # takes down a service somebody else depends on.
        owner = _port_owner()
        if owner:
            raise RuntimeError(
                f"port {MQTT_PORT} is already in use by a broker this service did "
                f"not start; stop it first. Listener: {owner}")

        # Write mosquitto config — listen on all interfaces, open or password-only
        if username is not None:
            _write_password_file(username, password)
            conf_lines = config_lines(MQTT_PORT, MOSQUITTO_LOG, PASSWORD_FILE)
        else:
            conf_lines = config_lines(MQTT_PORT, MOSQUITTO_LOG)
        with open(MOSQUITTO_CONF, "w") as f:
            f.write("\n".join(conf_lines) + "\n")

        # Start mosquitto
        _proc = subprocess.Popen(
            ["mosquitto", "-c", MOSQUITTO_CONF],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )

        # Wait for it to initialise
        time.sleep(1.0)
        if _proc.poll() is not None:
            out = _proc.stdout.read().decode(errors="replace")
            _active = False
            raise RuntimeError(f"mosquitto failed to start: {out[:500]}")

        _active = True
        _auth_user = username
        logger.info("MQTT broker started on port %d (%s)", MQTT_PORT,
                    f"auth: user {username}" if username else "open")
        return {"port": MQTT_PORT, "auth": username is not None}


def stop():
    """Stop the mosquitto broker."""
    global _active, _proc, _auth_user

    with _lock:
        _kill_proc(_proc)
        _proc = None
        _active = False
        _auth_user = None
        logger.info("MQTT broker stopped")


def status():
    """Return broker status dict."""
    global _active

    with _lock:
        running = _active and _proc is not None and _proc.poll() is None
        # If process died unexpectedly, update state
        if _active and not running:
            _active = False
        return {
            "running": running,
            "port": MQTT_PORT if running else None,
            "auth": running and _auth_user is not None,
        }


def subscriptions(since=0.0, address=None):
    """SUBSCRIBE records from the broker's log (FR-041); [] when there is none.

    The log is kept across broker restarts, so `since` (Pi epoch seconds)
    selects the records of one test.
    """
    try:
        with open(MOSQUITTO_LOG, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - SUBSCRIPTION_LOG_TAIL))
            data = f.read().decode(errors="replace")
    except FileNotFoundError:
        return []
    return parse_subscriptions(data.splitlines(), since, address)
