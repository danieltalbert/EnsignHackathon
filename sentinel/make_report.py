"""
Builds WAKEUP_REPORT.md from the orchestrator state: ranked runs, the winner,
before/after vs the base models, seed variance, red flags, and the exact steps
to put the winning model into Ollama and point the app at it.

Called automatically at the end of run_sweep.py; also runnable standalone:
    python make_report.py            # reads run_state.json -> WAKEUP_REPORT.md
"""

from __future__ import annotations

import json
import statistics
from datetime import datetime


def _f(x, pct=False):
    if x is None:
        return "-"
    return f"{x*100:.1f}%" if pct else f"{x}"


def _row(cells):
    return "| " + " | ".join(cells) + " |"


def _sweep_table(st: dict) -> str:
    hdr = ["run", "base", "lr", "dev tt_acc", "dev FP", "test tt_acc",
           "test hard-FP", "json ok", "composite", "sec"]
    lines = [_row(hdr), _row(["---"] * len(hdr))]
    rows = []
    for name, r in st["runs"].items():
        if not name.startswith("sweep_") or r.get("status") != "done":
            continue
        s = r["summary"]
        c = r["cfg"]
        rows.append((s.get("composite") or -1, [
            name, c["base_model"].split("/")[-1], f"{c['lr']:g}",
            _f(s.get("dev_tt_acc"), True), _f(s.get("dev_fp"), True),
            _f(s.get("test_tt_acc"), True), _f(s.get("test_hard_fp"), True),
            _f(s.get("test_json_valid"), True), _f(s.get("composite")),
            _f(s.get("seconds")),
        ]))
    for _, cells in sorted(rows, reverse=True):
        lines.append(_row(cells))
    return "\n".join(lines) if rows else "_No successful sweep runs._"


def _baseline_block(st: dict) -> str:
    out = []
    for name in ("base_e4b", "base_e2b"):
        r = st["runs"].get(name)
        if r and r.get("status") == "done":
            s = r["summary"]
            out.append(f"- **{name}** (no fine-tune): test tt_acc {_f(s.get('test_tt_acc'), True)}, "
                       f"test FP {_f(s.get('test_fp'), True)}, json ok {_f(s.get('test_json_valid'), True)}")
    return "\n".join(out) if out else "_Baselines unavailable._"


def _winner_block(st: dict) -> str:
    w = st.get("winner")
    if not w:
        return "**No winner selected** (sweep incomplete). See red flags below."
    finals = [r for n, r in st["runs"].items()
              if n.startswith("final_") and r.get("status") == "done"]
    accs = [r["summary"].get("test_tt_acc") for r in finals
            if r["summary"].get("test_tt_acc") is not None]
    best = None
    if finals:
        best = max(finals, key=lambda r: (r["summary"].get("composite") or -1))

    lines = [f"**Winner config:** `{w['run_name']}`  "
             f"(`{w['cfg']['base_model'].split('/')[-1]}`, lr {w['cfg']['lr']:g}, 3 epochs, LoRA r16)"]
    if accs:
        mean = statistics.mean(accs)
        sd = statistics.pstdev(accs) if len(accs) > 1 else 0.0
        lines.append(f"**Seed variance (test tt_acc across {len(accs)} seeds):** "
                     f"{mean*100:.1f}% ± {sd*100:.1f}%")
    if best:
        s = best["summary"]
        lines.append(f"**Best seed:** `{best['cfg']['run_name']}`  "
                     f"test tt_acc {_f(s.get('test_tt_acc'), True)}, "
                     f"test FP {_f(s.get('test_fp'), True)}, "
                     f"hard-neg FP {_f(s.get('test_hard_fp'), True)}, "
                     f"json ok {_f(s.get('test_json_valid'), True)}")
        lines.append(f"**GGUF (on Modal volume):** `{s.get('gguf') or 'export pending/failed'}`")

    # before/after
    base_name = "base_e4b" if "E4B" in w["cfg"]["base_model"] else "base_e2b"
    base = st["runs"].get(base_name, {}).get("summary", {})
    if best and base.get("test_tt_acc") is not None:
        delta = (best["summary"].get("test_tt_acc") or 0) - base["test_tt_acc"]
        lines.append(f"**Before vs after ({base_name} -> winner):** "
                     f"test tt_acc {_f(base.get('test_tt_acc'), True)} -> "
                     f"{_f(best['summary'].get('test_tt_acc'), True)}  "
                     f"(**{delta*100:+.1f} pts**)")
    return "\n".join(lines)


def _red_flags(st: dict) -> str:
    flags = []
    failed = [n for n, r in st["runs"].items() if r.get("status") == "failed"]
    if failed:
        flags.append(f"- {len(failed)} job(s) failed: {', '.join(failed)}. See orchestrator.log.")
    for n, r in st["runs"].items():
        if r.get("status") != "done":
            continue
        s = r["summary"]
        if (s.get("test_json_valid") or 1) < 0.95:
            flags.append(f"- `{n}` json-valid {_f(s.get('test_json_valid'), True)} (<95%): "
                         "pass OUTPUT_JSON_SCHEMA in Ollama's `format` field to force valid JSON.")
        if (s.get("test_fp") or 0) > 0.10 and n.startswith(("sweep_", "final_")):
            flags.append(f"- `{n}` benign false-positive rate {_f(s.get('test_fp'), True)} (>10%): "
                         "add more hard negatives and retrain, or the tool will nag users.")
    w = st.get("winner")
    if w:
        comp = st["runs"][w["run_name"]]["summary"].get("composite")
        if comp is not None and comp < 0.6:
            flags.append(f"- Winner composite {comp} is low. Consider more epochs or more data "
                         "before relying on it in the demo.")
    return "\n".join(flags) if flags else "_None._"


def _merge_steps(st: dict) -> str:
    w = st.get("winner")
    final_run = None
    best = None
    finals = [(n, r) for n, r in st["runs"].items()
              if n.startswith("final_") and r.get("status") == "done"]
    if finals:
        best = max(finals, key=lambda kv: (kv[1]["summary"].get("composite") or -1))
        final_run = best[0]
    gguf_path = (best[1]["summary"].get("gguf") if best else None) or "gguf/<winner-run>"
    rel = gguf_path.replace("/vol/", "")  # path inside the volume

    return f"""\
1. Pull the winning GGUF off the Modal volume to the PC that runs Ollama:
   ```
   modal volume get {('sentinel-vol ' + rel)} ./sentinel-model
   ls ./sentinel-model     # note the *.Q4_K_M.gguf file name
   ```
2. Create an Ollama Modelfile (`Modelfile.sentinel`). The system prompt is baked
   in so it matches training exactly:
   ```
   FROM ./sentinel-model/<the Q4_K_M file>
   TEMPLATE \"\"\"{_OLLAMA_TEMPLATE}\"\"\"
   PARAMETER stop "<turn|>"
   PARAMETER temperature 0
   PARAMETER num_ctx 2048
   SYSTEM \"\"\"{_SYSTEM_PROMPT}\"\"\"
   ```
3. Register it with Ollama on the PC:
   ```
   ollama create sentinel -f Modelfile.sentinel
   ollama run sentinel "{{...a test finding...}}"
   ```
4. Point the app at it: set `OLLAMA_MODEL=sentinel` in the repo `.env`
   (the Tailscale Funnel URL stays the same).
5. In the backend's Ollama call, send `format` = the JSON schema and
   `options.temperature = 0` so every response parses. The schema is
   `contract.OUTPUT_JSON_SCHEMA`; keep the one source of truth.
6. Verify end-to-end from the Mac:
   ```
   curl "$OLLAMA_URL/api/chat" -d '{{
     "model":"sentinel","stream":false,
     "messages":[{{"role":"user","content":"<paste one finding JSON>"}}]
   }}'
   ```
   If judgements look off, re-read WAKEUP_REPORT red flags before retraining.

Winner finalize run: `{final_run or '(none; sweep did not finish)'}`
"""


# Gemma-4 turn format for Ollama (same as the Modelfile Unsloth writes next to the
# GGUF). Without it Ollama may guess a template that doesn't match training.
_OLLAMA_TEMPLATE = """{{- range $i, $_ := .Messages }}
{{- $last := eq (len (slice $.Messages $i)) 1 }}
<|turn>{{ .Role }}
{{ .Content }}{{ if not $last }}<turn|>
{{ end }}
{{- end }}<turn|>
<|turn>model
"""

# imported lazily so make_report has no hard dep if contract moves
try:
    from contract import SYSTEM_PROMPT as _SYSTEM_PROMPT
except Exception:
    _SYSTEM_PROMPT = "(paste SYSTEM_PROMPT from contract.py)"


def build(st: dict, out_path: str = "WAKEUP_REPORT.md") -> str:
    started = st.get("started", "?")
    ended = st.get("ended", "(still running)")
    cost = st.get("est_cost_usd", "?")
    phase = st.get("phase", "?")
    n_done = sum(1 for r in st["runs"].values() if r.get("status") == "done")
    n_fail = sum(1 for r in st["runs"].values() if r.get("status") == "failed")

    md = f"""# Sentinel fine-tune: wake-up report

_Generated {datetime.utcnow().isoformat(timespec='seconds')}Z_

- Started: {started}
- Ended: {ended}
- Reached phase: **{phase}**
- Jobs: {n_done} done, {n_fail} failed
- Estimated GPU cost: **${cost}**

## TL;DR
{_winner_block(st)}

## Sweep results (ranked by composite = tt_acc - 0.5*FP)
{_sweep_table(st)}

## Baselines (before fine-tuning)
{_baseline_block(st)}

## Red flags
{_red_flags(st)}

## Do this next: put the winner in the app
{_merge_steps(st)}

---
_Metric notes: `tt_acc` = exact threat-type match; `FP` = benign findings wrongly
flagged (the cry-wolf rate); `hard-FP` = FP on the deliberately tricky benign
cases; `json ok` = fraction parseable before Ollama's `format` is even applied._
"""
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(md)
    return md


if __name__ == "__main__":
    with open("run_state.json") as fh:
        build(json.load(fh))
    print("wrote WAKEUP_REPORT.md")
