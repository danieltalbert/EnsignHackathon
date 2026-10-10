import os, re, json, time, hashlib, socket, platform, shutil
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template
import psutil
import harness

app = Flask(__name__)
app.register_blueprint(harness.blueprint)
HOME = Path.home().resolve()
ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
BASELINE = DATA / "baseline.json"
HASH_DB = ROOT / "known_hashes.txt"
APP_PID = os.getpid()
# Model runs on a remote Ollama server; endpoint comes from .env (see .env.example).
# The harness (harness/) sends it one finding at a time.
load_dotenv(ROOT / ".env")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "sentinel")
MAX_FILES = 3500
MAX_SYSTEM_FILES = 500
MAX_HASH_BYTES = 100 * 1024 * 1024

DATA.mkdir(exist_ok=True)
for path in (BASELINE, HASH_DB):
    if not path.exists():
        path.write_text("", encoding="utf-8") if path == HASH_DB else path.write_text("{}", encoding="utf-8")

def now():
    return datetime.now(timezone.utc).isoformat()

def human(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}"
        n /= 1024

def run_command(args, timeout=3):
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return p.stdout[:20000] if p.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""

def add(findings, category, severity, title, evidence, recommendation,
        confidence="medium", target=None):
    findings.append({
        "id": hashlib.sha256(
            (category + title + evidence).encode()
        ).hexdigest()[:12],
        "category": category,
        "severity": severity,
        "title": title,
        "evidence": str(evidence)[:1200],
        "recommendation": recommendation,
        "confidence": confidence,
        "target": target or {},  # pid/path/ip/port for the triage harness
    })

def read_baseline():
    try:
        return json.loads(BASELINE.read_text())
    except (OSError, ValueError):
        return {}

def write_baseline(data):
    tmp = BASELINE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, BASELINE)

def read_known_hashes():
    try:
        return {
            line.strip().lower()
            for line in HASH_DB.read_text().splitlines()
            if re.fullmatch(r"[a-fA-F0-9]{64}", line.strip())
        }
    except OSError:
        return set()

def sha256_file(path):
    try:
        if path.stat().st_size > MAX_HASH_BYTES:
            return None
        h = hashlib.sha256()
        with path.open("rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                h.update(block)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None

def process_snapshot(findings):
    rows, by_pid = [], {}
    # Prime CPU sampling.
    for p in psutil.process_iter():
        try:
            p.cpu_percent(None)
        except psutil.Error:
            pass
    time.sleep(.2)

    for p in psutil.process_iter():
        try:
            with p.oneshot():
                if p.pid == APP_PID:
                    continue
                info = p.as_dict(attrs=[
                    "pid", "ppid", "name", "username", "cmdline",
                    "exe", "create_time", "status"
                ])
                mem = p.memory_info().rss
                info.update({
                    "cpu": round(p.cpu_percent(None), 1),
                    "memory_bytes": mem,
                    "memory": human(mem),
                    "cmdline": (info.get("cmdline") or [])[:12],
                    "exe": info.get("exe") or "",
                })
                info["parent_name"] = ""
                rows.append(info)
                by_pid[info["pid"]] = info
        except (psutil.Error, OSError):
            continue

    # Rules are triage heuristics, not malware verdicts.
    suspicious_tools = {
        "nc", "ncat", "netcat", "socat", "xmrig", "minerd",
        "masscan", "nmap", "tcpdump"
    }
    obfuscation = re.compile(
        r"(base64\s+(-d|--decode)|\beval\s*\(|/dev/tcp/|"
        r"python\s+-c\s+['\"]|powershell.*-enc|"
        r"curl.{0,120}\|\s*(sh|bash))", re.I
    )
    for item in rows:
        parent = by_pid.get(item.get("ppid"))
        item["parent_name"] = parent.get("name", "") if parent else ""
        cmd = " ".join(item["cmdline"])
        name = (item.get("name") or "").lower()
        exe = item.get("exe") or ""
        t = {"pid": item["pid"], "name": item.get("name"), "exe": exe, "cpu": item["cpu"]}

        if obfuscation.search(cmd):
            add(findings, "Processes", "high",
                "Command pattern merits review",
                f"{name} (PID {item['pid']}), parent={item['parent_name']}; matched a suspicious command-line pattern.",
                "Inspect the complete command and its origin. Verify the script or download source before taking action.",
                "medium", target=t)

        if name in suspicious_tools or name in {
            "curl", "wget", "bash", "sh", "python", "python3",
            "perl", "ruby", "openssl", "busybox"
        }:
            add(findings, "Processes", "info",
                "Dual-use utility observed",
                f"{name} PID {item['pid']}; parent={item['parent_name']}.",
                "This utility has legitimate uses. Review its arguments, parent process, user, and timing if unexpected.",
                "low", target=t)

        if item["cpu"] >= 80:
            add(findings, "Processes", "medium",
                "High CPU usage",
                f"{name} PID {item['pid']} sampled at {item['cpu']}% CPU.",
                "Check whether this workload is expected. Review sustained usage and the executable's origin before classifying it as a cryptominer.",
                "low", target=t)

        if item["memory_bytes"] >= 1024**3:
            add(findings, "Processes", "info",
                "High memory consumer",
                f"{name} PID {item['pid']} uses {item['memory']}.",
                "Confirm this memory use is expected and close the application normally if it is no longer needed.",
                "low", target=t)

        # Linux usually has no universal Authenticode-style signature check.
        if exe and os.path.isfile(exe):
            try:
                st = os.stat(exe)
                if st.st_mode & 0o002:
                    add(findings, "Processes", "medium",
                        "World-writable executable",
                        f"{exe} is writable by all local users.",
                        "Verify the file's owner and package provenance. Correct permissions only after confirming the appropriate policy.",
                        "medium", target=t)
            except OSError:
                pass

        if parent and name in {"sh", "bash", "dash", "python", "python3", "perl"}:
            if parent.get("name", "").lower() in {"nginx", "apache2", "sshd", "cron", "crond"}:
                add(findings, "Processes", "medium",
                    "Sensitive parent-child process chain",
                    f"{parent.get('name')} PID {parent['pid']} spawned {name} PID {item['pid']}.",
                    "Validate the parent service's configuration and logs. These chains can be legitimate but deserve context.",
                    "low", target=t)

    rows.sort(key=lambda x: (x["cpu"], x["memory_bytes"]), reverse=True)
    return rows[:120]

def network_snapshot(findings):
    connections, errors = [], 0
    try:
        for c in psutil.net_connections(kind="inet"):
            local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            row = {
                "protocol": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                "local": local, "remote": remote or "—",
                "state": c.status or "UNKNOWN", "pid": c.pid,
            }
            connections.append(row)
            if c.status == "LISTEN":
                add(findings, "Network", "info", "Listening port",
                    f"{row['protocol']} {local}, PID {c.pid}.",
                    "Identify the owning process and confirm that the service should be listening. Check firewall exposure if applicable.",
                    "low", target={"ip": c.laddr.ip, "port": c.laddr.port, "pid": c.pid, "protocol": row["protocol"]})
    except (psutil.AccessDenied, OSError):
        errors += 1

    # ARP/neighbour table: snapshot for future comparisons.
    arp = []
    try:
        for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
            cols = line.split()
            if len(cols) >= 6:
                arp.append({"ip": cols[0], "mac": cols[3], "interface": cols[5]})
    except OSError:
        pass

    # Only locally available DNS evidence; do not claim this is a DNS history.
    dns_config = ""
    try:
        dns_config = "\n".join(
            line.strip() for line in Path("/etc/resolv.conf").read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )[:3000]
    except OSError:
        dns_config = "Resolver configuration unavailable"

    # Wi-Fi details if NetworkManager is present and exposes them.
    wifi = run_command([
        "nmcli", "-t", "-f", "IN-USE,SSID,SECURITY,SIGNAL",
        "device", "wifi", "list"
    ], timeout=3)
    if wifi:
        for line in wifi.splitlines()[:20]:
            parts = line.split(":")
            if len(parts) >= 4:
                security = parts[2].strip().upper()
                if security in {"", "--", "NONE", "OPEN"}:
                    add(findings, "Network", "medium", "Open Wi-Fi entry visible",
                        f"Visible network entry: {line[:180]}",
                        "Verify the network identity before connecting. Prefer a trusted network and a secure VPN when appropriate.",
                        "low", target={"wifi": line[:180]})

    old = read_baseline().get("network", {})
    old_arp = {x.get("ip"): x.get("mac") for x in old.get("arp", [])}
    for entry in arp:
        previous = old_arp.get(entry["ip"])
        if previous and previous.lower() != entry["mac"].lower():
            add(findings, "Network", "medium", "ARP mapping changed",
                f"{entry['ip']} changed from {previous} to {entry['mac']} on {entry['interface']}.",
                "Confirm the device and gateway identity. DHCP changes and virtual networks can explain legitimate changes.",
                "medium", target={"ip": entry["ip"], "mac": entry["mac"], "previous_mac": previous, "interface": entry["interface"]})

    # Per-process connection counts are useful context, not beacon detection.
    counts = {}
    for c in connections:
        if c["pid"]:
            counts[c["pid"]] = counts.get(c["pid"], 0) + 1
    for pid, count in counts.items():
        if count >= 80:
            add(findings, "Network", "info", "High connection count",
                f"PID {pid} has {count} visible socket entries.",
                "Identify the process and confirm whether its workload normally opens many connections.",
                "low", target={"pid": pid, "count": count})

    return {
        "connections": connections[:500],
        "arp": arp,
        "dns_resolver_config": dns_config,
        "wifi_entries": wifi.splitlines()[:20] if wifi else [],
        "permission_errors": errors,
        "limitations": [
            "No packet payload capture or complete DNS query history.",
            "Beaconing and upload volume require time-series traffic evidence.",
            "Wi-Fi visibility depends on NetworkManager and container access."
        ]
    }

def storage_snapshot(findings):
    previous = read_baseline().get("files", {})
    known = read_known_hashes()
    current, candidates = {}, []
    scanned = 0
    now_ts = time.time()
    old_days = 180
    executable_ext = {".sh", ".py", ".pl", ".rb", ".bin", ".elf", ".run", ".AppImage"}

    skip = {".cache", ".git", ".venv", "venv", "node_modules",
            "__pycache__", ".local/share/Trash"}
    for root, dirs, files in os.walk(HOME, followlinks=False):
        dirs[:] = [d for d in dirs if d not in skip and not d.startswith(".cache")]
        for name in files:
            path = Path(root) / name
            try:
                if path.is_symlink():
                    continue
                st = path.stat()
                scanned += 1
                key = str(path)
                age = max(0, int((now_ts - st.st_mtime) / 86400))
                current[key] = {"size": st.st_size, "mtime": int(st.st_mtime)}
                if st.st_size >= 50 * 1024**2 or age >= old_days:
                    candidates.append({
                        "path": key, "name": name, "size": st.st_size,
                        "size_label": human(st.st_size), "age_days": age,
                        "reason": ("Large file; review whether it is needed"
                                   if st.st_size >= 50 * 1024**2
                                   else "Not modified in 180+ days; review before removing")
                    })

                suffix = path.suffix.lower()
                is_exec = bool(st.st_mode & 0o111) or suffix in executable_ext
                if is_exec:
                    old = previous.get(key)
                    if old is None:
                        add(findings, "Storage", "medium", "Executable not in previous baseline",
                            f"{key} (size {human(st.st_size)}). This is only new relative to the previous successful scan.",
                            "Check the file's origin, owner, and package/source. First scan establishes a baseline; new does not mean malicious.",
                            "low", target={"path": key, "event": "new", "first_scan": not previous})
                    elif old.get("mtime") != int(st.st_mtime) or old.get("size") != st.st_size:
                        add(findings, "Storage", "info", "Executable changed since baseline",
                            f"{key} metadata changed since the previous scan.",
                            "Verify whether a legitimate update or installation explains the change.",
                            "low", target={"path": key, "event": "modified"})

                if scanned >= MAX_FILES:
                    break
            except (OSError, PermissionError):
                continue
        if scanned >= MAX_FILES:
            break

    # Hash known executable candidates only; no external reputation service.
    for candidate in candidates[:80]:
        path = Path(candidate["path"])
        if path.suffix.lower() in executable_ext or os.access(path, os.X_OK):
            digest = sha256_file(path)
            if digest and digest in known:
                add(findings, "Storage", "critical", "Hash matches local indicator list",
                    f"SHA-256 {digest} for {path}.",
                    "Treat as a high-priority lead, verify the indicator's provenance, and follow your incident-response process. Do not execute the file.",
                    "high", target={"path": str(path), "event": "detected", "sha256": digest})

    # A single snapshot cannot prove mass encryption; metadata changes between
    # baselines provide a cautious indicator only when a substantial pattern exists.
    changed = 0
    if previous:
        for key, info in current.items():
            old = previous.get(key)
            if old and info["mtime"] != old.get("mtime") and info["size"] != old.get("size"):
                changed += 1
        if changed >= 40:
            add(findings, "Storage", "medium", "Many files changed since baseline",
                f"{changed} files have both size and modification-time changes since the previous scan.",
                "Review recent activity and backups. This is not proof of ransomware; normal bulk edits, builds, or updates can cause this pattern.",
                "low", target={"count": changed})

    candidates.sort(key=lambda x: x["size"], reverse=True)
    return {
        "files_scanned": scanned,
        "truncated": scanned >= MAX_FILES,
        "total_candidate_count": len(candidates),
        "candidates": candidates[:100],
        "disk": {
            "total": psutil.disk_usage(str(HOME)).total,
            "used": psutil.disk_usage(str(HOME)).used,
            "free": psutil.disk_usage(str(HOME)).free,
            "percent": psutil.disk_usage(str(HOME)).percent,
        },
        "limitations": [
            "Only a bounded subset of the home directory is scanned.",
            "System-directory integrity is not fully audited in this build.",
            "Hash matching uses only locally supplied SHA-256 indicators.",
            "Mass encryption requires trustworthy change history."
        ],
    }

def system_report():
    vm = psutil.virtual_memory()
    du = psutil.disk_usage(str(HOME))
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "os": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "cpu_count": psutil.cpu_count(),
        "cpu_percent": psutil.cpu_percent(interval=.15),
        "ram_total": vm.total,
        "ram_used": vm.used,
        "ram_available": vm.available,
        "ram_percent": vm.percent,
        "disk_total": du.total,
        "disk_used": du.used,
        "disk_free": du.free,
        "disk_percent": du.percent,
        "scope": "Visible Linux environment; container and permission limitations apply."
    }

@app.after_request
def headers(response):
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
    return jsonify({"ok": True, "model": OLLAMA_MODEL})

@app.get("/api/system")
def api_system():
    return jsonify(system_report())

@app.post("/api/scan")
def scan():
    findings = []
    system = system_report()
    processes = process_snapshot(findings)
    network = network_snapshot(findings)
    storage = storage_snapshot(findings)

    # Baseline is updated after comparisons. Only metadata is stored.
    old = read_baseline()
    current_files = {}
    # storage_snapshot returns the user-facing results; rebuild a bounded
    # metadata baseline for future executable and change comparisons.
    scanned = 0
    skip = {".cache", ".git", ".venv", "venv", "node_modules", "__pycache__"}
    for root, dirs, files in os.walk(HOME, followlinks=False):
        dirs[:] = [d for d in dirs if d not in skip and not d.startswith(".cache")]
        for name in files:
            p = Path(root) / name
            try:
                if p.is_symlink():
                    continue
                st = p.stat()
                current_files[str(p)] = {"size": st.st_size, "mtime": int(st.st_mtime)}
                scanned += 1
                if scanned >= MAX_FILES:
                    break
            except OSError:
                continue
        if scanned >= MAX_FILES:
            break

    write_baseline({
        "timestamp": now(),
        "files": current_files,
        "network": {"arp": network["arp"]}
    })

    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("critical", "high", "medium", "info")}
    report = {
        "timestamp": now(),
        "system": system,
        "network": network,
        "storage": storage,
        "processes": processes,
        "findings": findings,
        "counts": counts,
        "baseline_existed": bool(old.get("timestamp")),
        "notice": "Snapshot assessment, not continuous monitoring or an antivirus verdict."
    }
    # Findings also go to the triage harness, one at a time (deduped there).
    harness.submit_scan(findings)
    return jsonify(report)

if __name__ == "__main__":
    harness.start({"processes": process_snapshot, "storage": storage_snapshot,
                   "network": network_snapshot})
    app.run(host="127.0.0.1", port=5000, debug=False)
