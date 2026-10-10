"""Cheap rules on the contract shape: skip the obviously normal, flag the rest.

screen(item) -> (skip, flags, level). Skipped items never reach the model. `level`
is the rule-only severity used while the model is offline. Tuned so no labeled
threat in sentinel/data is ever skipped (see harness/selftest.py).
"""
import re
from pathlib import Path
from . import config

SEV = ("none", "low", "medium", "high", "critical")
RULE_SEV = {"info": "low", "medium": "medium", "high": "high", "critical": "critical"}
TEMP = re.compile(r"(^/tmp/|^/var/tmp/|^/private/(var/)?tmp/|^/dev/shm/|/downloads/|\\downloads\\|"
                  r"\\appdata\\local\\temp\\|\\temp\\|\\appdata\\roaming\\|/\.[^/]+/[^/]*$|\\public\\)", re.I)
SYSTEM = re.compile(r"^(/system/|/usr/(bin|sbin|lib|libexec)/|/bin/|/sbin/|/applications/|"
                    r"/opt/homebrew/|/usr/local/(bin|cellar)/|/snap/|/usr/share/|"
                    r"c:\\windows\\|c:\\program files)", re.I)
BAD_CMD = re.compile(r"(base64|frombase64|-enc(odedcommand)?\b|\biex\b|invoke-expression|/dev/tcp/|"
                     r"(curl|wget)[^|]*\|\s*(ba|z)?sh|\beval\b|\bnc\b.*-e|bash\s+-i|downloadstring|"
                     r"mshta|regsvr32|certutil.*urlcache|python[0-9.]*\s+-c|osascript\s+-e|hidden)", re.I)
SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "explorer.exe", "winlogon.exe", "services.exe",
                "smss.exe", "kernel_task", "launchd", "systemd", "sshd", "cron", "kworker", "dwm.exe",
                "runtimebroker.exe", "taskhostw.exe", "conhost.exe", "rundll32.exe"}
RISKY_PORTS = {21, 23, 135, 139, 445, 1337, 3389, 4444, 5555, 5900, 6666, 6667, 31337}
SCRIPT_EXT = {".py", ".sh", ".rb", ".pl", ".js", ".ts", ".bash", ".zsh"}
DOWNLOAD_EXT = {".exe", ".msi", ".pkg", ".dmg", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".jar",
                ".app", ".deb", ".rpm", ".appimage", ".js", ".hta", ".lnk", ".iso"}
_git_cache = {}


def _in_git_tree(path):
    p = Path(path).parent
    for d in [p, *p.parents][:12]:
        if str(d) in _git_cache:
            return _git_cache[str(d)]
        if (d / ".git").exists():
            _git_cache[str(d)] = True
            return True
    _git_cache[str(p)] = False
    return False


def _processes(f, flags):
    exe, cmd, name = f.get("exe_path", ""), f.get("cmdline", ""), f.get("name", "").lower()
    if BAD_CMD.search(cmd):
        flags.append("obfuscated or download-and-run command line")
    if exe and TEMP.search(exe):
        flags.append("runs from a temp, downloads or hidden folder")
    if f.get("signed") is False:
        flags.append("unsigned program")
    if name in SYSTEM_NAMES and exe and not SYSTEM.search(exe):
        flags.append("system process name in an unusual location")
    if f.get("cpu_pct", 0) >= 80 and f.get("signed") is not True:
        flags.append("sustained high CPU from an unrecognized program")
    if f.get("remote_endpoints") and f.get("signed") is not True:
        flags.append("unrecognized program talking to the internet")
    if f.get("listening") and f.get("is_new"):
        flags.append("new program accepting inbound connections")
    trusted = f.get("signed") is True or (f.get("signed") is None and exe and SYSTEM.search(exe))
    return bool(trusted) and not flags


def _storage(f, ctx, flags):
    if f.get("kind") == "burst":
        if f.get("note_files"):
            flags.append("ransom-note-like files appeared")
        if f.get("ext_changes"):
            flags.append("file extensions were changed in bulk")
        if f.get("avg_entropy", 0) >= 7.2:
            flags.append("changed files look encrypted")
        if f.get("event") == "deleted":
            flags.append("many files deleted quickly")
        flags.append(f"{f.get('count', 'many')} files changed at once")
        return False
    path, ext = f.get("path", ""), (f.get("extension") or "").lower()
    if f.get("matches_local_indicator"):
        flags.append("matches the local known-bad hash list")
    if SYSTEM.search(path) and f.get("event") == "modified":
        flags.append("system file modified")
    if TEMP.search(path) and (ext in DOWNLOAD_EXT or f.get("is_executable")):
        flags.append("new program in a temp or downloads folder")
    if f.get("origin_url") and f.get("signed") is not True:
        flags.append("downloaded from the internet")
    if f.get("avg_entropy", 0) >= 7.2 and ext not in {".7z", ".zip", ".gz", ".rar", ".dmg", ".jpg", ".png", ".mp4"}:
        flags.append("content looks encrypted")
    if flags:
        return False
    if ctx.get("first_scan") or path.startswith(str(config.ROOT)):
        return True  # baseline being established / this app's own files
    if ext in SCRIPT_EXT and _in_git_tree(path):
        return True  # source code in a working tree
    if f.get("event") == "modified" and not SYSTEM.search(path):
        return True  # ordinary edit to a user file
    return f.get("event") == "new" and not f.get("is_executable") and ext not in DOWNLOAD_EXT


def _network(f, flags):
    if f.get("exposed_to") == "wan":
        flags.append("exposed to the open internet")
    if f.get("shares_mac_with"):
        flags.append("shares a hardware address with another device")
    if f.get("previous_mac"):
        flags.append("hardware address changed")
    ports = {p.get("port") for p in f.get("open_ports") or []}
    if ports & RISKY_PORTS:
        flags.append("commonly attacked or backdoor port open")
    if f.get("is_new") and not f.get("is_this_device"):
        flags.append("new device on the network")
    if f.get("is_this_device") and f.get("is_new") and ports:
        flags.append("newly opened port on this computer")
    if f.get("exposed_to") == "localhost":
        return not flags
    return not flags


def _backups(f, flags):
    total, changed = f.get("files_total") or 0, f.get("changed") or 0
    if f.get("missing"):
        flags.append(f"{f['missing']} backup files missing")
    if f.get("changed_exts"):
        flags.append("backup files renamed with new extensions")
    if (f.get("avg_entropy_changed") or 0) >= 7.0:
        flags.append("changed backup files look encrypted")
    if total and changed > total * 0.5:
        flags.append("most of the backup changed at once")
    if f.get("last_backup_hours", 0) > 1.5 * (f.get("expected_interval_hours") or 24):
        flags.append("backup is overdue")
    return not flags


STRONG = ("obfuscated", "ransom", "encrypted", "known-bad", "open internet", "hardware address",
          "backdoor", "missing", "system process name")


def screen(item, watched=False):
    inp, rule = item.get("input"), item.get("rule") or {}
    flags = []
    if inp is None:
        return False, flags, RULE_SEV.get(rule.get("severity"), "low")
    f, src = inp["finding"], inp["source"]
    normal = {"processes": lambda: _processes(f, flags), "storage": lambda: _storage(f, item.get("ctx") or {}, flags),
              "network": lambda: _network(f, flags), "backups": lambda: _backups(f, flags)}[src]()
    level = "low"
    if flags:
        level = "high" if any(s in x for x in flags for s in STRONG) else "medium"
    rs = RULE_SEV.get(rule.get("severity"))
    if rs and SEV.index(rs) > SEV.index(level):
        level = rs
    return (normal and not watched and rule.get("severity") != "critical"), flags, level
