"""ROUTER: severity -> log / notify / approval card, escalation triggers, and target resolution.

The model (and the escalation reviewer) only name tools. Every target here is read
from the finding the scanner produced, never from model output.
"""
from . import executor


def needs_escalation(j, item):
    """Reason to escalate, or None."""
    if j is None:
        return "the local model's reply failed validation twice"
    if j["escalate"]:
        return "the local model asked for a second opinion"
    if j["confidence"] == "low":
        return "the local model's confidence is low"
    if j["threat_type"] == "other_suspicious":
        return "the local model saw something outside its known threat types"
    if (item.get("rule") or {}).get("severity") == "critical" and j["severity"] in ("none", "low"):
        return "the local model disagrees with a critical rule match"
    return None


def route(severity):
    return "log" if severity == "none" else "notify" if severity == "low" else "approve"


def _host(endpoint):
    e = str(endpoint)
    if e.startswith("["):
        return e[1:].split("]")[0]
    return e.rsplit(":", 1)[0] if e.count(":") == 1 else e


def make(name, target, origin="model", reason=None):
    tool = executor.REGISTRY[name]
    ok = target is not None
    return {"name": name, "label": tool["label"], "detail": executor.describe(name, target) if ok else "",
            "target": target, "available": ok, "reason": None if ok else reason,
            "admin": executor.admin_hint(name) if tool["changes"] else "", "changes": tool["changes"],
            "reversible": tool["reversible"], "confirm": bool(tool.get("confirm")), "origin": origin,
            "state": "proposed" if ok else "unavailable", "message": ""}


def action(name, item, origin="model", guidance=""):
    """Card action for a tool the model proposed, with its target taken from the finding."""
    inp = item.get("input") or {}
    f, src, ctx = inp.get("finding") or {}, inp.get("source"), item.get("ctx") or {}
    pid = f.get("pid") if src == "processes" and isinstance(f.get("pid"), int) else None
    path = (f.get("path") if src == "storage" and f.get("kind") == "file"
            else f.get("exe_path") if src == "processes" else None)
    target, why = None, None
    if name == "kill_process":
        target = {"pid": pid, "name": f.get("name"), "exe": f.get("exe_path") or ctx.get("exe"),
                  "create_time": ctx.get("create_time")} if pid else None
        why = "This finding doesn't name a running process."
    elif name == "inspect_process":
        target = {"pid": pid, "name": f.get("name"), "create_time": ctx.get("create_time")} if pid else None
        why = "This finding doesn't name a running process."
    elif name in ("quarantine_file", "file_info"):
        target, why = ({"path": path} if path else None), "This finding doesn't name a single file."
    elif name == "disconnect_network":
        remote = ([_host(e) for e in f.get("remote_endpoints") or []] if src == "processes" else
                  [f["ip"]] if src == "network" and f.get("ip") and not f.get("is_this_device") else [])
        if remote:  # the finding names a remote address: block just that, not the whole machine
            name, target = "block_address", {"addresses": sorted(set(remote))}
        else:
            target = {}
    elif name == "close_port":
        ports = sorted({p["port"] for p in f.get("open_ports") or [] if isinstance(p, dict)
                        and isinstance(p.get("port"), int)}) if src == "network" and f.get("is_this_device") else []
        target, why = ({"ports": ports} if ports else None), "This finding doesn't name a port on this computer."
    elif name == "run_backup":
        target = {"backup_path": f["backup_path"]} if f.get("backup_path") else {}
    elif name == "restore_backup":
        target, why = ({"backup_path": f["backup_path"]} if f.get("backup_path") else None), "This finding doesn't name a backup."
    elif name == "monitor":
        target = {"key": item.get("key")}
    elif name == "guide_user":
        target = {"text": guidance}
    else:
        return None
    return make(name, target, origin, why)
