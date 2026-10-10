"""Harness configuration. Everything comes from .env / the environment."""
import os, ssl, platform, importlib.util
from pathlib import Path
import certifi
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / "harness"
STATE_DIR = HERE / "state"
QUARANTINE = HERE / "quarantine"
AUDIT_LOG = HERE / "audit.jsonl"
EVAL_TEST = ROOT / "sentinel" / "data" / "eval_test.jsonl"
load_dotenv(ROOT / ".env")  # no-op for keys already set in the real environment

def _env(key, default=""):
    return (os.getenv(key) or default).strip()

def _flag(key, default="0"):
    return _env(key, default).lower() in {"1", "true", "yes", "on"}

def _int(key, default):
    try:
        return max(1, int(_env(key, str(default))))
    except ValueError:
        return default

OLLAMA_URL = _env("OLLAMA_URL").rstrip("/")
OLLAMA_MODEL = _env("OLLAMA_MODEL", "sentinel")
GEMINI_API_KEY = _env("GEMINI_API_KEY")
GEMINI_MODEL = _env("GEMINI_MODEL", "gemma-4-31b-it")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent"
DEMO_MODE = _flag("DEMO_MODE")
ALWAYS_ACTIVE = _flag("ALWAYS_ACTIVE", "1")

JUDGE_TIMEOUT = _int("JUDGE_TIMEOUT", 90)
ESCALATE_TIMEOUT = _int("ESCALATE_TIMEOUT", 90)
HEALTH_INTERVAL = _int("HEALTH_INTERVAL", 15)
DEDUPE_TTL = _int("DEDUPE_TTL", 3600)

# Per-scanner mode table: always_active scanners run while Always-Active is on,
# scheduled ones run on their interval regardless, "off" disables. Seconds.
# Override any cell from .env, e.g. MODE_NETWORK=always_active, INTERVAL_STORAGE=600.
_DEFAULTS = (("processes", "always_active", 30), ("storage", "always_active", 300),
             ("network", "scheduled", 900), ("backups", "scheduled", 3600))
SCANNERS = {}
for _name, _mode, _sec in _DEFAULTS:
    _m = _env(f"MODE_{_name.upper()}", _mode).lower()
    SCANNERS[_name] = {"mode": _m if _m in {"always_active", "scheduled", "off"} else _mode,
                       "interval": _int(f"INTERVAL_{_name.upper()}", _sec)}

OS = {"Darwin": "macos", "Windows": "windows", "Linux": "linux"}.get(platform.system(), platform.system().lower())

# certifi covers Python installs that ship without a CA bundle (python.org macOS).
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.load_verify_locations(certifi.where())

def _load_contract():
    # Loaded by path so a pip package that happens to be named "sentinel" can't shadow it.
    spec = importlib.util.spec_from_file_location("sentinel_contract", ROOT / "sentinel" / "contract.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

contract = _load_contract()
