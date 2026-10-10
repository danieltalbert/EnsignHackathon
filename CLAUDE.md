# Sentinel Local

Hackathon consumer security app. Flask backend (`app.py`), vanilla JS frontend (`templates/index.html`, `static/app.js`, `static/style.css`).

## Ground rule: no new features, minimal changes
- Do not add features or redesign the UI.
- Do not rename, move, or rewrite existing code beyond the minimum needed for the task.
- Match the existing code style (compact Flask handlers, terse vanilla JS, no frameworks).

## Architecture (do not deviate)
- **App runs locally** on the user's own machine (`python app.py` → http://127.0.0.1:5000). All scanning and system access (psutil, filesystem, network snapshot) happen locally.
- **Model runs remotely**: Gemma 4 E4B (`gemma4:e4b`) in Ollama on a home PC, exposed over HTTPS via Tailscale Funnel.
- The app calls `POST {OLLAMA_URL}/api/chat` (non-streaming, `format: "json"`) from `ollama_analysis()` in `app.py`, triggered only when the user clicks "Analyze with Gemma" (`/api/analyze`).
- Any user on any machine must reach the model with zero extra setup: no Tailscale, no local Ollama, no localhost/LAN dependency for the model.
- If the model is unset, unreachable, slow (>90s), or returns unreadable output, `/api/analyze` returns `{"available": false, "message": ...}` and the UI shows it. Scanning never depends on the model.

## Env setup
```
cp .env.example .env   # then fill in the real OLLAMA_URL
python -m pip install -r requirements.txt
python app.py
```
- `OLLAMA_URL`: base URL of the Ollama server (no trailing `/api`). No default; if empty, AI analysis reports "not configured".
- `OLLAMA_MODEL`: defaults to `gemma4:e4b`.
- `.env` is loaded by python-dotenv at startup; real shell env vars take precedence.
- **The repo is public: never commit `.env` or the Funnel URL.** Share `.env` with teammates privately.
