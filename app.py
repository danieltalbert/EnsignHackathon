from flask import Flask, jsonify, render_template, request
import os
import platform
import socket
import time
import shutil
import psutil
from datetime import datetime, timezone

app = Flask(__name__)
APP_PID = os.getpid()
STARTED_AT = time.time()

# Keep this app local. Do not enable debug mode or bind to 0.0.0.0.
HOME = os.path.expanduser("~")
SKIP_DIRS = {
    ".cache", ".local/share/Trash", ".git", "node_modules",
    ".venv", "venv", "__pycache__"
}


def human_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}"
        n /= 1024


def safe_process(p):
    try:
        with p.oneshot():
            if p.pid == APP_PID:
                return None
            return {
                "pid": p.pid,
                "name": p.name() or "Unknown",
                "username": p.username() if p.pid else "",
                "cpu_percent": p.cpu_percent(interval=None),
                "memory_percent": round(p.memory_percent(), 2),
                "memory_bytes": p.memory_info().rss,
                "memory": human_bytes(p.memory_info().rss),
                "status": p.status(),
                "created": datetime.fromtimestamp(
                    p.create_time(), timezone.utc
                ).isoformat(),
                "exe": p.exe() or "",
                "cmdline": (p.cmdline() or [])[:8],
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied,
            psutil.ZombieProcess, OSError):
        return None


def system_report():
    vm = psutil.virtual_memory()
    du = psutil.disk_usage(HOME)
    try:
        boot = datetime.fromtimestamp(
            psutil.boot_time(), timezone.utc
        ).isoformat()
    except (OSError, ValueError):
        boot = None

    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "os": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": psutil.cpu_count(),
        "cpu_percent": psutil.cpu_percent(interval=0.15),
        "ram_total": vm.total,
        "ram_used": vm.used,
        "ram_available": vm.available,
        "ram_percent": vm.percent,
        "ram_total_label": human_bytes(vm.total),
        "ram_used_label": human_bytes(vm.used),
        "disk_total": du.total,
        "disk_used": du.used,
        "disk_free": du.free,
        "disk_percent": du.percent,
        "disk_total_label": human_bytes(du.total),
        "disk_used_label": human_bytes(du.used),
        "disk_free_label": human_bytes(du.free),
        "boot_time": boot,
        "app_uptime_seconds": int(time.time() - STARTED_AT),
        "scope": "Current Linux environment; permissions limit visibility.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def process_snapshot():
    # Prime CPU counters, then sample briefly for useful readings.
    processes = []
    for p in psutil.process_iter():
        try:
            p.cpu_percent(interval=None)
        except (psutil.Error, OSError):
            pass
    time.sleep(0.25)

    for p in psutil.process_iter():
        item = safe_process(p)
        if item:
            processes.append(item)

    processes.sort(
        key=lambda x: (x["cpu_percent"], x["memory_bytes"]),
        reverse=True
    )
    return processes[:100]


def network_snapshot(duration=5):
    # Observes local socket metadata, not packet payloads.
    # No raw packet capture and no scans of remote hosts.
    duration = max(1, min(int(duration), 15))
    samples = {}
    errors = 0
    end = time.monotonic() + duration

    while True:
        try:
            for c in psutil.net_connections(kind="inet"):
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                key = (c.family, c.type, laddr, raddr, c.status, c.pid)
                samples[key] = {
                    "family": "IPv6" if c.family == socket.AF_INET6 else "IPv4",
                    "type": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                    "local": laddr,
                    "remote": raddr or "—",
                    "status": c.status or "UNKNOWN",
                    "pid": c.pid,
                }
        except (psutil.AccessDenied, OSError):
            errors += 1

        if time.monotonic() >= end:
            break
        time.sleep(0.5)

    rows = list(samples.values())
    # Heuristics only: unusual is not the same as malicious.
    for row in rows:
        flags = []
        if row["status"] == "LISTEN":
            flags.append("Listening port — verify expected service")
        if row["remote"] != "—" and row["status"] == "ESTABLISHED":
            flags.append("Active connection — review if unfamiliar")
        row["review_notes"] = flags

    return {
        "duration_seconds": duration,
        "unique_socket_observations": len(rows),
        "permission_errors": errors,
        "connections": rows[:300],
        "limitations": (
            "Socket metadata only; not packet contents or a malware verdict. "
            "Some connections may be hidden by container permissions."
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def storage_scan(max_files=1500):
    # Walk only the user's home directory; skip common noisy folders.
    # Bounded results keep a large home directory from freezing the demo.
    found = []
    scanned = 0
    now = time.time()
    cutoff_old = 180 * 24 * 60 * 60
    cutoff_recent = 30 * 24 * 60 * 60

    for root, dirs, files in os.walk(HOME, followlinks=False):
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS and not d.startswith(".cache")
        ]
        for name in files:
            path = os.path.join(root, name)
            try:
                if os.path.islink(path):
                    continue
                st = os.stat(path, follow_symlinks=False)
                scanned += 1
                age_days = max(0, int((now - st.st_mtime) / 86400))
                if st.st_size >= 50 * 1024 * 1024 or age_days >= 180:
                    if st.st_size >= 1024 * 1024:
                        reason = "Large file; review whether still needed"
                    else:
                        reason = "Not modified in 180+ days; review before removing"
                    if age_days < 30:
                        reason = "Large file modified recently; review before removing"
                    found.append({
                        "path": path,
                        "name": name,
                        "size": st.st_size,
                        "size_label": human_bytes(st.st_size),
                        "age_days": age_days,
                        "reason": reason,
                        "modified": datetime.fromtimestamp(
                            st.st_mtime, timezone.utc
                        ).isoformat(),
                    })
                if scanned >= max_files:
                    break
            except (PermissionError, FileNotFoundError, OSError):
                continue
        if scanned >= max_files:
            break

    found.sort(key=lambda f: f["size"], reverse=True)
    return {
        "root": HOME,
        "files_scanned": scanned,
        "scan_limit": max_files,
        "truncated": scanned >= max_files,
        "candidates": found[:100],
        "note": (
            "Recommendations only. Age is based on modification time, "
            "not proof that a file is unused. Nothing is deleted."
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "service": "Sentinel Local"})


@app.get("/api/system")
def api_system():
    return jsonify(system_report())


@app.get("/api/processes")
def api_processes():
    return jsonify({"processes": process_snapshot()})


@app.get("/api/network")
def api_network():
    try:
        duration = int(request.args.get("seconds", "5"))
    except ValueError:
        duration = 5
    return jsonify(network_snapshot(duration))


@app.get("/api/storage")
def api_storage():
    return jsonify(storage_scan())


@app.get("/api/report")
def api_report():
    # AI can later consume this single normalized JSON object.
    return jsonify({
        "system": system_report(),
        "processes": process_snapshot(),
        "storage": storage_scan(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ai_summary": None,
        "ai_integration": "Add local model analysis here.",
    })


if __name__ == "__main__":
    # Local-only binding; debug mode deliberately disabled.
    app.run(host="127.0.0.1", port=5000, debug=False)
