"""Consent-based elevation for ONE approved action.

Always the OS's own prompt (macOS admin dialog, pkexec, UAC), launched as a fresh
process per action, so nothing is cached or kept elevated afterwards. Sentinel
never sees, stores or types a password.
"""
import shlex, shutil, subprocess
from . import config

PROMPT = {"macos": "macOS administrator password dialog",
          "linux": "pkexec (polkit) authentication dialog",
          "windows": "Windows UAC consent prompt (runas)"}


class Declined(Exception):
    """The user cancelled (or ignored) the OS consent prompt."""


class Unsupported(Exception):
    """This OS can't do the action (yet)."""


def q(s):
    return shlex.quote(str(s))


def _applescript(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def run(script, why):
    """Run one approved action as admin. `script` is a POSIX sh string on macOS/Linux,
    or a list of cmd.exe lines on Windows (prefix a line with "?" if it may fail).
    Returns (returncode, output). Raises Declined / Unsupported."""
    try:
        if config.OS == "macos":
            osa = (f"do shell script {_applescript(script)} with prompt "
                   f"{_applescript('Sentinel needs administrator access to ' + why + '.')} "
                   "with administrator privileges")
            p = subprocess.run(["osascript", "-e", osa], capture_output=True, text=True, timeout=600)
            if p.returncode and ("-128" in p.stderr or "User canceled" in p.stderr):
                raise Declined()
            return p.returncode, (p.stdout + p.stderr).strip()
        if config.OS == "linux":
            pk = shutil.which("pkexec")
            if not pk:
                raise Unsupported("pkexec isn't installed, so Sentinel can't ask for admin rights on this system.")
            p = subprocess.run([pk, "/bin/sh", "-c", script], capture_output=True, text=True, timeout=600)
            if p.returncode in (126, 127):  # dismissed / not authorized
                raise Declined()
            return p.returncode, (p.stdout + p.stderr).strip()
        if config.OS == "windows":
            return _windows(script)
    except subprocess.TimeoutExpired:
        raise Declined()
    raise Unsupported("Not supported on this OS yet.")


def _windows(lines):
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    bat, log = config.STATE_DIR / "elevated.cmd", config.STATE_DIR / "elevated.log"
    log.unlink(missing_ok=True)
    body = ["@echo off", "set FAILED="]
    for line in lines:
        cmd, may_fail = (line[1:], True) if line.startswith("?") else (line, False)
        body.append(f'{cmd} >> "{log}" 2>&1' + ("" if may_fail else " || set FAILED=1"))
    body += ["if defined FAILED exit /b 1", "exit /b 0"]
    bat.write_text("\r\n".join(body) + "\r\n", encoding="utf-8")
    path = str(bat).replace("'", "''")
    ps = ("try { $p = Start-Process -FilePath $env:ComSpec -ArgumentList '/c', '\"" + path + "\"' "
          "-Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode } "
          "catch { if ($_.Exception.Message -match 'cancel') { 'DECLINED' } else { $_.Exception.Message }; exit 1223 }")
    p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                       capture_output=True, text=True, timeout=600)
    if "DECLINED" in p.stdout:
        raise Declined()
    try:
        out = log.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        out = p.stdout + p.stderr
    return p.returncode, out.strip()
