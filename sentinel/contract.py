"""
Sentinel contract: the single source of truth shared by the dataset generator,
the trainer, the eval harness, and the production app.

Nothing here imports torch / unsloth / modal, so it is safe to import anywhere
(local machine, Modal container, Ollama-side tooling). Pure stdlib only.

The INPUT is one finding from a device scanner. The OUTPUT is Sentinel's
judgement of that one finding. The model judges; the app decides what runs.
"""

from __future__ import annotations

import json
import re
from typing import Any

# ---------------------------------------------------------------------------
# Enums (closed vocabularies). Keep these frozen; the app policy table keys off
# them, and the generator / eval both validate against them.
# ---------------------------------------------------------------------------

SOURCES = ("processes", "storage", "network", "backups")
OSES = ("windows", "macos", "linux")
MODES = ("manual", "scheduled", "always_active")

THREAT_TYPES_BY_SOURCE: dict[str, tuple[str, ...]] = {
    "processes": ("cryptominer", "masquerading", "malicious_script", "remote_access_tool"),
    "storage": ("ransomware", "malicious_download", "mass_deletion", "system_file_tampering"),
    "network": ("rogue_device", "exposed_service", "backdoor_port", "arp_spoofing"),
    "backups": ("backup_deleted", "backup_encrypted", "backup_tampering", "stale_backup"),
}
# valid for any source
THREAT_TYPES_ANY = ("none", "other_suspicious")

ALL_THREAT_TYPES = tuple(
    sorted(set(THREAT_TYPES_ANY) | {t for v in THREAT_TYPES_BY_SOURCE.values() for t in v})
)

SEVERITIES = ("none", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")

ACTIONS = (
    "none",
    "monitor",
    "kill_process",
    "quarantine_file",
    "disconnect_network",
    "close_port",
    "restore_backup",
    "run_backup",
    "guide_user",
)

MAX_ACTIONS = 2
MAX_EVIDENCE = 3
MIN_EVIDENCE = 2

# ---------------------------------------------------------------------------
# Prompt. Training and inference MUST use this identical text, or the fine-tune
# will not transfer to production. Edit here, nowhere else.
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are Sentinel, a local device-security triage engine. You receive ONE finding "
    "from a system scanner and judge only that finding. Reply with ONLY a single JSON "
    "object and no other text.\n"
    "\n"
    "Schema:\n"
    '  finding_id: copy the id from the input exactly.\n'
    "  evidence: 2-3 short strings, each citing one specific signal from the input that "
    "drove your judgement.\n"
    f"  threat_type: one of {list(ALL_THREAT_TYPES)}.\n"
    f"  severity: one of {list(SEVERITIES)}.\n"
    f"  confidence: one of {list(CONFIDENCES)}.\n"
    f"  actions: 0 to {MAX_ACTIONS} proposed actions from {list(ACTIONS)}.\n"
    "  explanation: ONE plain-English sentence a non-technical person understands. No jargon.\n"
    "  escalate: boolean; true when you are unsure, or when severity is medium or higher but "
    "confidence is low.\n"
    "\n"
    "Rules:\n"
    "- Normal, expected activity is threat_type \"none\", severity \"none\", actions [] or "
    "[\"monitor\"].\n"
    "- High resource use, many file changes, open ports, or new devices are NOT automatically "
    "threats. Weigh who did it, where it ran, and whether it is signed/known before flagging.\n"
    "- Use only values present in the input. Never invent paths, pids, or ids.\n"
    "- You propose actions only. Nothing runs without the user's approval, so never imply an "
    "action has already happened."
)


def build_messages(finding: dict[str, Any]) -> list[dict[str, str]]:
    """Return chat messages for one finding. Used by trainer AND eval."""
    user = (
        "Analyze this scanner finding and return the JSON judgement.\n\n"
        + json.dumps(finding, ensure_ascii=False, sort_keys=True)
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


# JSON schema handed to Ollama's `format` field in production so every response
# parses. Mirrors validate_output below.
OUTPUT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "finding_id",
        "evidence",
        "threat_type",
        "severity",
        "confidence",
        "actions",
        "explanation",
        "escalate",
    ],
    "properties": {
        "finding_id": {"type": "string"},
        "evidence": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": MIN_EVIDENCE,
            "maxItems": MAX_EVIDENCE,
        },
        "threat_type": {"type": "string", "enum": list(ALL_THREAT_TYPES)},
        "severity": {"type": "string", "enum": list(SEVERITIES)},
        "confidence": {"type": "string", "enum": list(CONFIDENCES)},
        "actions": {
            "type": "array",
            "items": {"type": "string", "enum": list(ACTIONS)},
            "maxItems": MAX_ACTIONS,
        },
        "explanation": {"type": "string"},
        "escalate": {"type": "boolean"},
    },
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# Validation + lenient parsing (no third-party deps, safe in any container)
# ---------------------------------------------------------------------------

def validate_output(obj: Any) -> list[str]:
    """Return a list of problems with a candidate output. Empty list == valid."""
    errs: list[str] = []
    if not isinstance(obj, dict):
        return ["output is not a JSON object"]

    required = OUTPUT_JSON_SCHEMA["required"]
    for key in required:
        if key not in obj:
            errs.append(f"missing key: {key}")
    if errs:
        return errs

    if not isinstance(obj["finding_id"], str) or not obj["finding_id"]:
        errs.append("finding_id must be a non-empty string")

    ev = obj["evidence"]
    if not isinstance(ev, list) or not all(isinstance(x, str) and x.strip() for x in ev):
        errs.append("evidence must be a list of non-empty strings")
    elif not (MIN_EVIDENCE <= len(ev) <= MAX_EVIDENCE):
        errs.append(f"evidence must have {MIN_EVIDENCE}-{MAX_EVIDENCE} items")

    if obj["threat_type"] not in ALL_THREAT_TYPES:
        errs.append(f"threat_type not in vocabulary: {obj['threat_type']!r}")
    if obj["severity"] not in SEVERITIES:
        errs.append(f"severity not in vocabulary: {obj['severity']!r}")
    if obj["confidence"] not in CONFIDENCES:
        errs.append(f"confidence not in vocabulary: {obj['confidence']!r}")

    ac = obj["actions"]
    if not isinstance(ac, list):
        errs.append("actions must be a list")
    else:
        if len(ac) > MAX_ACTIONS:
            errs.append(f"actions has more than {MAX_ACTIONS} items")
        for a in ac:
            if a not in ACTIONS:
                errs.append(f"action not in vocabulary: {a!r}")

    if not isinstance(obj["explanation"], str) or not obj["explanation"].strip():
        errs.append("explanation must be a non-empty string")
    if not isinstance(obj["escalate"], bool):
        errs.append("escalate must be a boolean")
    return errs


_OBJ_RE = re.compile(r"\{.*\}", re.DOTALL)


def extract_json(text: str) -> dict[str, Any] | None:
    """Pull the first balanced JSON object out of raw model text. Returns None
    if nothing parseable is found. Mirrors what a lenient client would do; in
    production Ollama's `format` makes this unnecessary, so this is a floor."""
    if not isinstance(text, str):
        return None
    # Fast path: whole string is JSON.
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except Exception:
        pass
    # Scan for the first balanced {...}.
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    chunk = text[start : i + 1]
                    try:
                        obj = json.loads(chunk)
                        if isinstance(obj, dict):
                            return obj
                    except Exception:
                        break
        start = text.find("{", start + 1)
    return None


def canonical_key(finding: dict[str, Any]) -> str:
    """Stable key for cross-split dedup. Ignores finding_id (it is random)."""
    f = {k: v for k, v in finding.items() if k != "finding_id"}
    return json.dumps(f, sort_keys=True, ensure_ascii=False)


if __name__ == "__main__":
    # Tiny self-check.
    good = {
        "finding_id": "proc-1",
        "evidence": ["a", "b"],
        "threat_type": "cryptominer",
        "severity": "high",
        "confidence": "high",
        "actions": ["kill_process", "quarantine_file"],
        "explanation": "A hidden program is using your computer to mine crypto.",
        "escalate": False,
    }
    assert validate_output(good) == [], validate_output(good)
    assert validate_output({"finding_id": "x"})  # missing keys -> errors
    assert extract_json('noise {"a": 1} tail') == {"a": 1}
    print("contract.py OK:", len(ALL_THREAT_TYPES), "threat types,", len(ACTIONS), "actions")
