# Sentinel Local

Manual, read-only defensive security assessment for the accessible Linux environment.

## Start
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py

Open http://127.0.0.1:5000

## Ollama
Install/start Ollama separately, then:
ollama pull gemma4:e4b
ollama run gemma4:e4b

The app uses http://127.0.0.1:11434 by default.
Optional configuration:
OLLAMA_URL=http://127.0.0.1:11434 OLLAMA_MODEL=gemma4:e4b python app.py

## Safety and limits
- Only scans when requested. No automatic remediation.
- Stores a local metadata baseline in data/baseline.json.
- Network snapshots do not include packet contents or complete DNS query history.
- Beaconing and unusual uploads need time-series evidence.
- First scan establishes a baseline; comparisons become useful on later scans.
- File scanning is bounded. System-wide integrity checks are not comprehensive.
- Hash indicators are local only; populate known_hashes.txt with trusted SHA-256 indicators.
- Process heuristics can flag legitimate tools. Linux executable metadata is not a universal digital-signature check.
- ChromeOS Linux containers limit process, network, Wi-Fi, and filesystem visibility.
- Do not expose Flask's development server to a network; debug mode is off.
