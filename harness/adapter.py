"""Scanner finding (app.py add()) -> contract input. Targets come from the scanner, never the model."""
import os, re, time, socket, hashlib, threading, ipaddress, subprocess
from pathlib import Path
import psutil
from . import config

PREFIX = {"processes": "proc", "storage": "stor", "network": "netw", "backups": "back"}
CONTRACT_OS = config.OS if config.OS in ("windows", "macos", "linux") else "linux"
NEW_WINDOW = 1800  # seconds an executable / listening port counts as "new"
_signers, _lock = {}, threading.Lock()


class Novelty:
    """First-seen times. The first observation is the baseline (not new)."""
    def __init__(self):
        self.seen, self.primed = {}, False

    def observe(self, keys):
        now = time.time()
        with _lock:
            for k in keys:
                self.seen.setdefault(k, now if self.primed else 0)
            self.primed = True

    def is_new(self, key):
        with _lock:
            t = self.seen.get(key)
        return bool(t) and time.time() - t < NEW_WINDOW


EXES, PORTS = Novelty(), Novelty()


def _safe(fn, default=None):
    try:
        return fn()
    except (psutil.Error, OSError, ValueError):
        return default


def signer(exe):
    """(signed, signer) for an executable, cached. (None, None) where the OS has no check."""
    if not exe or not os.path.isfile(exe):
        return None, None
    if exe in _signers:
        return _signers[exe]
    res = (None, None)
    try:
        if config.OS == "macos":
            p = subprocess.run(["codesign", "-dv", "--verbose=2", exe],
                               capture_output=True, text=True, timeout=5)
            auth = re.search(r"^Authority=(.+)$", p.stderr, re.M)
            res = (bool(auth), auth.group(1).strip() if auth else None) if p.returncode == 0 else (False, None)
        elif config.OS == "windows":
            ps = ("$s=Get-AuthenticodeSignature -LiteralPath '" + exe.replace("'", "''") +
                  "'; \"$($s.Status)|$($s.SignerCertificate.Subject)\"")
            p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                               capture_output=True, text=True, timeout=10)
            status, _, subject = p.stdout.strip().partition("|")
            cn = re.search(r"CN=([^,]+)", subject)
            res = (status == "Valid", cn.group(1).strip('" ') if cn else None)
    except (OSError, subprocess.TimeoutExpired):
        pass
    _signers[exe] = res
    return res


def origin_url(path):
    """Download source if the OS recorded one (macOS WhereFroms, Windows Zone.Identifier)."""
    try:
        if config.OS == "macos":
            out = subprocess.run(["mdls", "-raw", "-name", "kMDItemWhereFroms", path],
                                 capture_output=True, text=True, timeout=3).stdout
            m = re.search(r'"(https?://[^"]+)"', out)
            return m.group(1) if m else None
        if config.OS == "windows":
            with open(path + ":Zone.Identifier", encoding="utf-8", errors="ignore") as f:
                m = re.search(r"^HostUrl=(.+)$", f.read(), re.M)
                return m.group(1).strip() if m else None
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def _endpoint(ip, port):
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def observe_processes():
    exes = set()
    for p in psutil.process_iter(["exe"]):
        if p.info.get("exe"):
            exes.add(p.info["exe"])
    EXES.observe(exes)


def _process(t, rule):
    pid = t.get("pid")
    if not isinstance(pid, int):
        return None, None
    p = psutil.Process(pid)  # NoSuchProcess -> caller drops the finding
    with p.oneshot():
        name, ct = p.name(), p.create_time()
        exe = _safe(p.exe, "") or ""
        cmd = _safe(p.cmdline, []) or []
        user = _safe(p.username)
        parent = _safe(lambda: p.parent().name() if p.parent() else None)
        rss = _safe(lambda: p.memory_info().rss)
        conns = _safe(lambda: p.net_connections(kind="inet"), []) or []
    f = {"name": name, "pid": pid}
    if exe:
        f["exe_path"] = exe
    if cmd:
        f["cmdline"] = " ".join(cmd)[:400]
    if parent:
        f["parent_name"] = parent
    if user:
        f["user"] = user
    if isinstance(t.get("cpu"), (int, float)):
        f["cpu_pct"] = t["cpu"]
    if rss:
        f["mem_mb"] = round(rss / 1024**2)
    signed, who = signer(exe)
    if signed is not None:
        f["signed"] = signed
        if who:
            f["signer"] = who
    remote = sorted({_endpoint(c.raddr.ip, c.raddr.port) for c in conns
                     if c.raddr and not _loopback(c.raddr.ip)})[:5]
    if remote:
        f["remote_endpoints"] = remote
    if any(c.status == "LISTEN" for c in conns):
        f["listening"] = True
    if exe:
        f["is_new"] = EXES.is_new(exe)
    if t.get("count"):
        f["connection_count"] = t["count"]
    ctx = {"pid": pid, "name": name, "exe": exe, "create_time": ct, "user": user}
    return f, ctx


def _loopback(ip):
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_loopback
    except ValueError:
        return False


def _storage(t, rule):
    if "count" in t:  # many files changed since baseline
        return {"kind": "burst", "event": "modified", "count": t["count"]}, {}
    path = t.get("path")
    if not path:
        return None, None
    st = os.stat(path)
    f = {"kind": "file", "path": path, "event": t.get("event", "modified"),
         "size_bytes": st.st_size, "is_executable": True, "is_new": t.get("event") == "new"}
    if Path(path).suffix:
        f["extension"] = Path(path).suffix.lower()
    url = origin_url(path)
    if url:
        f["origin_url"] = url
    if t.get("sha256"):
        f["matches_local_indicator"] = True
    return f, {"path": path, "mtime": int(st.st_mtime), "first_scan": bool(t.get("first_scan"))}


def _network(t, rule):
    if t.get("port") is not None:  # listening socket on this device
        ip, port = t.get("ip") or "0.0.0.0", t["port"]
        try:
            service = socket.getservbyport(port, "tcp" if t.get("protocol", "TCP") == "TCP" else "udp")
        except OSError:
            service = "unknown"
        f = {"ip": ip, "is_this_device": True, "is_new": PORTS.is_new(port),
             "open_ports": [{"port": port, "service": service}],
             "exposed_to": "localhost" if _loopback(ip) else "lan"}
        name = _safe(lambda: psutil.Process(t["pid"]).name()) if t.get("pid") else None
        if name:
            f["bound_process"] = name
        return f, {"pid": t.get("pid"), "name": name}
    if t.get("ip") and t.get("mac"):  # ARP mapping changed
        return {"ip": t["ip"], "mac": t["mac"], "is_new": False,
                "previous_mac": t.get("previous_mac")}, {}
    return None, None  # e.g. Wi-Fi entries have no address: rules-only


def _key(source, rule, f, ctx):
    if source == "processes":
        return f"proc|{rule['title']}|{f['pid']}|{int(ctx['create_time'])}"
    if source == "storage":
        return f"stor|{rule['title']}|{f.get('path', 'burst')}|{ctx.get('mtime', '')}"
    if f.get("open_ports"):
        return f"netw|listen|{f['ip']}|{f['open_ports'][0]['port']}|{ctx.get('pid')}"
    return f"netw|{rule['title']}|{f.get('ip')}|{f.get('mac')}"


def prepare(findings):
    """Update novelty baselines from a scan batch before adapting it."""
    if any(x.get("category") in ("Processes", "Network") for x in findings):
        observe_processes()
    ports = [x["target"]["port"] for x in findings if x.get("target", {}).get("port") is not None]
    if ports:
        PORTS.observe(ports)


def adapt(finding, mode):
    """Return a pipeline item, or None if the target vanished. item['input'] is None
    for findings the contract can't express (they stay rules-only)."""
    t = finding.get("target") or {}
    rule = {k: finding.get(k) for k in ("id", "category", "severity", "title", "evidence", "recommendation")}
    source = {"Processes": "processes", "Storage": "storage", "Network": "network"}.get(finding.get("category"))
    if source == "network" and t.get("pid") and t.get("count"):
        source = "processes"  # "High connection count" is about a process, not a host
    build = {"processes": _process, "storage": _storage, "network": _network}.get(source)
    try:
        f, ctx = build(t, rule) if build else (None, None)
    except (psutil.NoSuchProcess, FileNotFoundError):
        return None
    except (psutil.Error, OSError):
        f, ctx = None, None
    if f is None:
        return {"key": f"rule|{rule['id']}", "input": None, "ctx": {}, "rule": rule, "origin": "scan"}
    key = _key(source, rule, f, ctx)
    fid = f"{PREFIX[source]}-{hashlib.sha1(key.encode()).hexdigest()[:10]}"
    return {"key": key, "origin": "scan", "rule": rule, "ctx": ctx,
            "input": {"finding_id": fid, "source": source, "os": CONTRACT_OS, "mode": mode, "finding": f}}
