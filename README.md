# Sentinel Local

A local-first system overview prototype for a hackathon.

## Features
- System/OS, CPU, memory and disk summary
- Process snapshot with sampled CPU and RAM use
- Short snapshot of visible local network socket metadata
- Bounded home-directory storage scan with manual-review recommendations
- JSON API intended for a later local AI integration

## Run on Linux / ChromeOS Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in the browser. Stop with Ctrl+C.

If venv creation or pip fails, check your Linux environment's Python/pip packages.
Do not run this app with sudo unless you have a specific reason.

## API
- `GET /api/health`
- `GET /api/system`
- `GET /api/processes`
- `GET /api/network?seconds=5` (maximum 15 seconds)
- `GET /api/storage`
- `GET /api/report` (combined JSON payload for AI)

## Safety and limitations
- Binds only to 127.0.0.1; do not expose it to a public or shared network.
- No file deletion or process termination.
- Network feature observes socket metadata, not packet payloads.
- This is not an antivirus. Heuristics do not establish malware.
- Permissions and the ChromeOS Linux container limit visibility.
- Storage traversal is capped at 1,500 files per request.
- The development server is for local prototyping, not production deployment.
