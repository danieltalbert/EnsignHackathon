# Sentinel Local

Hackathon consumer security app. Flask backend (`app.py`), vanilla JS frontend (`templates/index.html`, `static/app.js`, `static/style.css`).

## Ground rule: no new features, minimal changes
- Do not add features or redesign the UI.
- Do not rename, move, or rewrite existing code beyond the minimum needed for the task.
- Match the existing code style (compact Flask handlers, terse vanilla JS, no frameworks).

## Architecture (do not deviate)
- **App runs locally** on the user's own machine (`python app.py` → http://127.0.0.1:5000). All scanning and system access (psutil, filesystem, network snapshot) happen locally.
- **Model runs remotely**: the fine-tuned `sentinel` model (Gemma 4 E4B, see `sentinel/`) in Ollama on a home PC, exposed over HTTPS via Tailscale Funnel.
- **Triage harness** (`harness/`, started by `app.py`): scanner finding → `adapter` (contract shape from `sentinel/contract.py`) → `prefilter` (skip the obviously normal) → deduped queue → `judge` (`POST {OLLAMA_URL}/api/chat`, one finding, `think:false`, `format=OUTPUT_JSON_SCHEMA`, temperature 0, retry once, else escalate) → `router` (none=log, low=notify, medium+=approval card) → `escalate` (Gemini `GEMINI_MODEL` when the judgement says escalate, confidence is low, or threat is other_suspicious) → `executor` (only on Approve).
- **Safety**: the model only names tools; targets (pid/path/ip/port) come from the finding. Nothing that changes the machine runs without the user's Approve, and elevation is per action through the OS's own prompt. `DEMO_MODE=1` makes every state-changing action a dry run. Every action is appended to `harness/audit.jsonl`.
- Any user on any machine must reach the model with zero extra setup: no Tailscale, no local Ollama, no localhost/LAN dependency for the model.
- If the model is unset, unreachable or slow (>90s), the harness keeps scanning and queueing on the prefilter rules alone, shows "model offline", and resumes judging when it's back. Scanning never depends on the model.

## Env setup
```
cp .env.example .env   # then fill in the real OLLAMA_URL
python -m pip install -r requirements.txt
python app.py
```
- `OLLAMA_URL`: base URL of the Ollama server (no trailing `/api`). No default; if empty, AI analysis reports "not configured".
- `OLLAMA_MODEL`: defaults to `sentinel`.
- `GEMINI_API_KEY` / `GEMINI_MODEL`: escalation reviewer (optional). `DEMO_MODE=1`: dry-run actions + "Run demo". Scanner modes/intervals: see `.env.example`.
- `.env` is loaded by python-dotenv at startup; real shell env vars take precedence.
- **The repo is public: never commit `.env` or the Funnel URL.** Share `.env` with teammates privately.
