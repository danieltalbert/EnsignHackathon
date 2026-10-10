"""EXECUTOR: tool registry, per-OS implementations, DEMO_MODE dry-run, append-only audit log.

Targets always come from the finding (see router.action); the model only names tools.
State-changing tools run only when approved=True, i.e. the user clicked Approve.
"""
import os, re, json, time, shutil, hashlib, threading, subprocess
from datetime import datetime, timezone
from pathlib import Path
import psutil
from . import config, elevate, firewall, adapter
from .elevate import q, Declined, Unsupported

ALL = ("macos", "linux", "windows")
PROTECTED = re.compile(r"^(/System/|/usr/(bin|sbin|lib|libexec)/|/bin/|/sbin/|/private/var/db/|"
                       r"/boot/|/etc/|[a-z]:\\windows\\)", re.I)
_audit_lock = threading.Lock()


class Abort(Exception):
    """Target no longer matches the finding (e.g. PID reused). Nothing was changed."""


def now():
    return datetime.now(timezone.utc).isoformat()


def R(status, message, **kw):
    return {"status": status, "message": message, **kw}


# --- audit log ----------------------------------------------------------------

def audit(**rec):
    line = json.dumps({"ts": now(), **rec}, default=str)
    with _audit_lock:
        with open(config.AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def recent_audit(n=50):
    try:
        lines = config.AUDIT_LOG.read_text(encoding="utf-8").splitlines()[-n:]
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


# --- processes ----------------------------------------------------------------

def _verify(t):
    """Re-check the PID still is the process the finding described (PIDs get reused)."""
    pid = t.get("pid")
    if not isinstance(pid, int) or pid <= 1 or pid in (os.getpid(), os.getppid()):
        raise ValueError("This finding has no process Sentinel may stop.")
    try:
        p = psutil.Process(pid)
        name, ct = p.name(), p.create_time()
    except psutil.NoSuchProcess:
        raise Abort(f"{t.get('name') or 'The process'} (PID {pid}) has already exited.")
    if t.get("name") and name != t["name"]:
        raise Abort(f"PID {pid} is now '{name}', not '{t['name']}'. PIDs get reused, so nothing was stopped.")
    if t.get("create_time") and abs(ct - t["create_time"]) > 1:
        raise Abort(f"PID {pid} was restarted since the scan, so nothing was stopped. Rescan to refresh.")
    exe = adapter._safe(p.exe)
    if t.get("exe") and exe and exe != t["exe"]:
        raise Abort(f"PID {pid} now runs {exe}, not {t['exe']}, so nothing was stopped.")
    return p


def _same_user(p):
    me = adapter._safe(lambda: psutil.Process().username())
    return bool(me) and adapter._safe(p.username) == me


def _kill(t):
    p = _verify(t)
    pid, name = p.pid, p.name()
    if _same_user(p):
        p.terminate()
        _, alive = psutil.wait_procs([p], timeout=3)
        if alive:
            p.kill()
            psutil.wait_procs([p], timeout=2)
        return R("done", f"Stopped {name} (PID {pid}).")
    why = f"stop {name} (PID {pid})"
    if config.OS == "windows":
        if not re.fullmatch(r"[\w .()+-]{1,120}", name):
            raise ValueError("Unexpected characters in the process name; not passing it to taskkill.")
        rc, out = elevate.run([f'taskkill /F /FI "PID eq {pid}" /FI "IMAGENAME eq {name}"'], why)
    else:
        lst = " ".join(subprocess.run(["ps", "-p", str(pid), "-o", "lstart="], capture_output=True,
                                      text=True, timeout=3).stdout.split())
        if not lst:
            raise Abort(f"{name} (PID {pid}) has already exited.")
        # Re-checked inside the elevated shell too, in case the PID is reused while the prompt is open.
        script = (f'if [ "$(ps -p {pid} -o lstart= | xargs)" = {q(lst)} ]; '
                  f"then kill -TERM {pid}; else exit 3; fi")
        rc, out = elevate.run(script, why)
        if rc == 3:
            raise Abort(f"PID {pid} changed while the admin prompt was open, so nothing was stopped.")
    if rc:
        return R("failed", out[-300:] or f"exit code {rc}", elevated=True)
    time.sleep(1)
    running = psutil.pid_exists(pid) and adapter._safe(lambda: psutil.Process(pid).create_time()) == p.create_time()
    return R("done", f"Sent {name} (PID {pid}) a stop signal" + ("; it is still shutting down." if running else " and it exited."),
             elevated=True)


# --- files --------------------------------------------------------------------

def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _quarantine(t):
    src = Path(t.get("path") or "")
    if not src.is_absolute() or src.is_symlink() or not src.is_file():
        raise Abort("The file in this finding no longer exists (or isn't a regular file).")
    if PROTECTED.search(str(src)) or config.ROOT in src.parents:
        raise ValueError("Refusing to quarantine a protected system file or Sentinel's own files.")
    config.QUARANTINE.mkdir(parents=True, exist_ok=True)
    st = src.stat()
    qid = f"{int(time.time())}-{hashlib.sha1(str(src).encode()).hexdigest()[:8]}"
    dst = config.QUARANTINE / f"{qid}.bin"  # no original extension: never double-clickable
    elevated = False
    try:
        shutil.move(str(src), str(dst))
    except PermissionError:
        elevated = True
        why = f"move {src.name} into quarantine"
        rc, out = (elevate.run([f'move /Y "{src}" "{dst}"'], why) if config.OS == "windows"
                   else elevate.run(f"mv {q(src)} {q(dst)} && chown {os.getuid()} {q(dst)}", why))
        if rc:
            return R("failed", out[-300:] or f"exit code {rc}", elevated=True)
    try:
        os.chmod(dst, 0o400)  # read-only, not executable
    except OSError:
        pass
    meta = {"qid": qid, "original_path": str(src), "sha256": _sha256(dst), "quarantined_at": now(),
            "size": st.st_size, "mode": st.st_mode & 0o7777,
            "uid": getattr(st, "st_uid", None), "gid": getattr(st, "st_gid", None)}
    (config.QUARANTINE / f"{qid}.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    return R("done", f"Moved {src.name} to quarantine (sha256 {meta['sha256'][:12]}…). It can be restored.",
             elevated=elevated, undo={"qid": qid, "path": str(src)})


def _restore(t):
    qid = str(t.get("qid") or "")
    if not re.fullmatch(r"\d+-[0-9a-f]{8}", qid):
        raise ValueError("No quarantine record for this file.")
    meta_path = config.QUARANTINE / f"{qid}.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    src, dst = config.QUARANTINE / f"{qid}.bin", Path(meta["original_path"])
    if dst.exists():
        raise ValueError("A file already exists at the original location; not overwriting it.")
    elevated = False
    try:
        shutil.move(str(src), str(dst))
        os.chmod(dst, meta["mode"])
    except PermissionError:
        elevated = True
        why = f"restore {dst.name} from quarantine"
        if config.OS == "windows":
            rc, out = elevate.run([f'move /Y "{src}" "{dst}"'], why)
        else:
            owner = f"{meta['uid']}:{meta['gid']}" if meta.get("uid") is not None else str(os.getuid())
            rc, out = elevate.run(f"mv {q(src)} {q(dst)} && chown {owner} {q(dst)} && chmod {meta['mode']:o} {q(dst)}", why)
        if rc:
            return R("failed", out[-300:] or f"exit code {rc}", elevated=True)
    meta["restored_at"] = now()
    meta_path.write_text(json.dumps(meta, indent=1), encoding="utf-8")
    return R("done", f"Restored {dst.name} to {dst.parent}.", elevated=elevated)


# --- network ------------------------------------------------------------------

def _fw(op, values, why, done_msg, undo=None):
    old, new = firewall.plan(op, values)
    if {k: old[k] for k in ("isolated", "blocked", "ports")} == {k: new[k] for k in ("isolated", "blocked", "ports")}:
        return R("done", "Already in place; nothing to change.")
    firewall.apply(old, new, why)
    return R("done", done_msg, elevated=True, **({"undo": undo} if undo else {}))


def _isolate(t):
    ips = firewall.endpoint_ips()
    if not ips:
        raise ValueError("Can't resolve the model endpoint, so isolating would cut Sentinel off too. Not isolating.")
    return _fw("isolate", None, "isolate this computer from the network",
               f"Isolated. Only the Sentinel model endpoint ({len(ips)} address(es)) and DNS are reachable. "
               "Use Undo isolation to reconnect.", undo={})


def _undo_isolation(t):
    return _fw("undo_isolation", None, "remove Sentinel's network isolation", "Network isolation removed.")


def _block(t):
    ips = firewall.addresses(t.get("addresses"))
    return _fw("block", ips, f"block {', '.join(ips)}", f"Blocked traffic to and from {', '.join(ips)}.",
               undo={"addresses": ips})


def _unblock(t):
    ips = [str(x) for x in t.get("addresses") or []]
    return _fw("unblock", ips, f"unblock {', '.join(ips)}", f"Unblocked {', '.join(ips)}.")


def _close_port(t):
    ports = firewall.ports(t.get("ports"))
    p = ", ".join(map(str, ports))
    return _fw("close_port", ports, f"block inbound port {p}",
               f"Blocked inbound connections to port {p} in the firewall (the service itself was left running).",
               undo={"ports": ports})


def _reopen_port(t):
    ports = firewall.ports(t.get("ports"))
    p = ", ".join(map(str, ports))
    return _fw("reopen_port", ports, f"reopen port {p}", f"Port {p} reopened.")


# --- read-only ----------------------------------------------------------------

def _inspect_process(t):
    p = _verify(t)
    with p.oneshot():
        info = {"name": p.name(), "pid": p.pid, "exe": adapter._safe(p.exe), "user": adapter._safe(p.username),
                "started": datetime.fromtimestamp(p.create_time()).isoformat(timespec="seconds"),
                "cmdline": " ".join(adapter._safe(p.cmdline, []) or [])[:300],
                "parents": [x.name() for x in (adapter._safe(p.parents, []) or [])[:3]],
                "connections": sorted({f"{c.raddr.ip}:{c.raddr.port}" for c in
                                       (adapter._safe(lambda: p.net_connections(kind="inet"), []) or []) if c.raddr})[:8]}
    signed, who = adapter.signer(info["exe"])
    info["signer"] = who if signed else ("unsigned" if signed is False else "unknown")
    return R("done", f"{info['name']} (PID {info['pid']}) run by {info['user']}, started {info['started']}, "
                     f"parents {' > '.join(info['parents']) or 'none'}, signer {info['signer']}, "
                     f"{len(info['connections'])} remote connection(s).", data=info)


def _file_info(t):
    path = Path(t.get("path") or "")
    if not path.is_file():
        raise Abort("The file in this finding no longer exists.")
    st = path.stat()
    digest = _sha256(path) if st.st_size <= 200 * 1024**2 else None
    signed, who = adapter.signer(str(path))
    data = {"path": str(path), "size": st.st_size, "modified": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
            "mode": oct(st.st_mode & 0o7777), "sha256": digest, "signer": who, "origin_url": adapter.origin_url(str(path))}
    return R("done", f"{path.name}: {st.st_size} bytes, modified {data['modified']}, sha256 {(digest or 'too large')[:16]}, "
                     f"signer {who or 'none'}{', from ' + data['origin_url'] if data['origin_url'] else ''}.", data=data)


def _monitor(t):
    return R("done", "Added to the watchlist: Sentinel re-checks it on every scan and never skips it as normal.")


def _guide(t):
    return R("done", t.get("text") or "No extra guidance for this finding.")


# --- registry -----------------------------------------------------------------
# Each tool: label, what it does (shown to the escalation model), whether it changes the
# machine, reversible + its undo tool, needs_admin per OS, and a per-OS implementation.
# A tool missing an OS in `impl` reports "not supported on this OS yet".

def _every(fn):
    return {o: fn for o in ALL}


REGISTRY = {
    "kill_process": dict(label="Stop process", changes=True, reversible=False, impl=_every(_kill),
                         needs_admin=_every("if the process belongs to another user"),
                         about="Stop the process named in the finding (re-verified first, since PIDs get reused)."),
    "quarantine_file": dict(label="Quarantine file", changes=True, reversible=True, undo="restore_file",
                            impl=_every(_quarantine), needs_admin=_every("if its folder isn't writable by you"),
                            about="Move the file named in the finding into Sentinel's quarantine folder with a "
                                  "restore record (path, hash, time). Never deletes."),
    "restore_file": dict(label="Restore file", changes=True, reversible=True, internal=True, impl=_every(_restore),
                         needs_admin=_every("if the original folder isn't writable by you"),
                         about="Put a quarantined file back where it was."),
    "disconnect_network": dict(label="Isolate network", changes=True, reversible=True, undo="undo_isolation",
                               impl=_every(_isolate), needs_admin=_every(True),
                               about="Isolate this computer: firewall blocks everything except Sentinel's model "
                                     "endpoint and DNS. If the finding names a remote address, only that address "
                                     "is blocked instead."),
    "undo_isolation": dict(label="Undo isolation", changes=True, reversible=True, internal=True,
                           impl=_every(_undo_isolation), needs_admin=_every(True), about="Remove network isolation."),
    "block_address": dict(label="Block address", changes=True, reversible=True, undo="unblock_address", internal=True,
                          impl=_every(_block), needs_admin=_every(True),
                          about="Block traffic to and from the remote address named in the finding."),
    "unblock_address": dict(label="Unblock address", changes=True, reversible=True, internal=True,
                            impl=_every(_unblock), needs_admin=_every(True), about="Remove an address block."),
    "close_port": dict(label="Close port", changes=True, reversible=True, undo="reopen_port",
                       impl=_every(_close_port), needs_admin=_every(True),
                       about="Block inbound connections to the port named in the finding in the OS firewall "
                             "(reversible; does not kill the service)."),
    "reopen_port": dict(label="Reopen port", changes=True, reversible=True, internal=True,
                        impl=_every(_reopen_port), needs_admin=_every(True), about="Remove a port block."),
    "run_backup": dict(label="Run backup", changes=True, reversible=False, impl={}, needs_admin=_every(False),
                       about="Run the app's backup routine."),
    "restore_backup": dict(label="Restore backup", changes=True, reversible=False, confirm=True, impl={},
                           needs_admin=_every(False), about="Restore files from the backup named in the finding."),
    "monitor": dict(label="Monitor", changes=False, reversible=True, impl=_every(_monitor), needs_admin=_every(False),
                    about="Keep watching this item: re-check it every scan and never skip it as normal."),
    "guide_user": dict(label="Show guidance", changes=False, reversible=True, impl=_every(_guide),
                       needs_admin=_every(False), about="Explain to the user what to do next, in plain language."),
    "inspect_process": dict(label="Inspect process", changes=False, reversible=True, impl=_every(_inspect_process),
                            needs_admin=_every(False), about="Read-only: details of the process in the finding "
                                                             "(path, user, parents, signer, connections)."),
    "file_info": dict(label="File details", changes=False, reversible=True, impl=_every(_file_info),
                      needs_admin=_every(False), about="Read-only: size, hash, signer and download source of the "
                                                       "file in the finding."),
}
NO_BACKUP = "This build has no backup routine yet, so Sentinel can't run or restore backups."


def admin_hint(name):
    need = REGISTRY[name]["needs_admin"].get(config.OS, False)
    return "admin" if need is True else ("may need admin" if need else "")


def describe(name, t):
    t = t or {}
    return {
        "kill_process": lambda: f"stop {t.get('name') or 'the process'} (PID {t.get('pid')})",
        "quarantine_file": lambda: f"move {t.get('path')} into quarantine with a restore record",
        "restore_file": lambda: f"restore {t.get('path')} from quarantine",
        "disconnect_network": lambda: "isolate this computer (allow only the Sentinel model endpoint and DNS)",
        "undo_isolation": lambda: "remove network isolation",
        "block_address": lambda: f"block traffic to and from {', '.join(map(str, t.get('addresses') or []))}",
        "unblock_address": lambda: f"unblock {', '.join(map(str, t.get('addresses') or []))}",
        "close_port": lambda: f"block inbound port {', '.join(map(str, t.get('ports') or []))} in the firewall",
        "reopen_port": lambda: f"reopen port {', '.join(map(str, t.get('ports') or []))}",
        "run_backup": lambda: "run a backup" + (f" of {t['backup_path']}" if t.get("backup_path") else ""),
        "restore_backup": lambda: f"restore files from {t.get('backup_path')}",
        "monitor": lambda: "add this to the watchlist",
        "guide_user": lambda: "show plain-language guidance",
        "inspect_process": lambda: f"inspect PID {t.get('pid')}",
        "file_info": lambda: f"read details of {t.get('path')}",
    }.get(name, lambda: name)()


def execute(name, target, *, card_id=None, finding_id=None, approved=False, confirm=False, demo_target=False):
    tool = REGISTRY.get(name)
    rec = dict(finding_id=finding_id, card_id=card_id, action=name, target=target,
               approved_by_user=approved, elevated=False, dry_run=False)
    prompt = None
    if not tool:
        res = R("unsupported", f"Unknown action '{name}'.")
    elif tool["changes"] and not approved:
        res = R("refused", "Actions that change this computer only run after you click Approve.")
    elif tool.get("confirm") and not confirm:
        return R("needs_confirm", "Restoring a backup overwrites current files. Confirm to continue.")
    elif tool["impl"].get(config.OS) is None:
        res = R("unsupported", NO_BACKUP if name in ("run_backup", "restore_backup") else "Not supported on this OS yet.")
    elif config.DEMO_MODE and tool["changes"]:
        need = tool["needs_admin"].get(config.OS)
        prompt = (elevate.PROMPT[config.OS] if need is True else
                  f"{elevate.PROMPT[config.OS]} ({need})" if need else "none")
        rec["dry_run"] = True
        res = R("dry_run", f"DEMO_MODE dry run: would {describe(name, target)}. Elevation prompt: {prompt}.",
                **({"undo": target} if tool.get("undo") else {}))
    elif demo_target and name in ("inspect_process", "file_info"):
        res = R("done", f"Demo replay: would {describe(name, target)}; the target is recorded test data, "
                        "so nothing on this machine was inspected.")
    else:
        try:
            res = tool["impl"][config.OS](target or {})
        except Declined:
            res = R("declined", "You cancelled the admin prompt, so nothing was changed. The card stays open.")
        except Abort as e:
            res = R("aborted", str(e))
        except Unsupported as e:
            res = R("unsupported", str(e))
        except (ValueError, KeyError) as e:
            res = R("refused", str(e).strip("'\""))
        except Exception as e:  # never crash the harness on a failed action
            res = R("failed", f"{type(e).__name__}: {str(e)[:200]}")
    rec.update(elevated=bool(res.get("elevated")), elevation_prompt=prompt, result=res["status"],
               message=res["message"], error=res["message"] if res["status"] in ("failed", "refused") else None)
    audit(**rec)
    return res
