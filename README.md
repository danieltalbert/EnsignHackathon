# Sentinel Local

Manual, read-only defensive security assessment for the accessible Linux environment.

## Start
```
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

## Model and triage
Copy `.env.example` to `.env` and set `OLLAMA_URL` (the team's Ollama server) and, optionally,
`GEMINI_API_KEY` for escalation. `python app.py` starts the triage harness in the background:
each finding is judged on its own by the `sentinel` model and anything that needs action
shows up as a card in panel 06 with Approve / Ignore. Set `DEMO_MODE=1` for a stage-safe run
(every action is a dry run, plus a "Run demo" button that replays labeled test findings).
Actions are logged to `harness/audit.jsonl`. Use http://127.0.0.1:5000, not localhost, on macOS
(AirPlay Receiver also listens on port 5000).

## Safety and limits
- Always-Active monitoring (processes, storage) can be switched off in the top bar. Nothing is changed on the machine without your Approve.
- Stores a local metadata baseline in data/baseline.json.
- Network snapshots do not include packet contents or complete DNS query history.
- Beaconing and unusual uploads need time-series evidence.
- First scan establishes a baseline; comparisons become useful on later scans.
- File scanning is bounded. System-wide integrity checks are not comprehensive.
- Hash indicators are local only; populate known_hashes.txt with trusted SHA-256 indicators.
- Process heuristics can flag legitimate tools. Linux executable metadata is not a universal digital-signature check.
- ChromeOS Linux containers limit process, network, Wi-Fi, and filesystem visibility.
- Do not expose Flask's development server to a network; debug mode is off.
