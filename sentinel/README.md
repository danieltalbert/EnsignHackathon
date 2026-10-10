# Sentinel: fine-tune pipeline (AI side)

The model half of the hackathon security tool. Everything here produces one
thing: a small, fine-tuned **Gemma 4** model that reads ONE scanner finding and
returns a strict-JSON judgement, ready to drop into Ollama and call from the app.

It is built to run **overnight, unattended**, on Modal. You launch it, go to
sleep, and wake up to `WAKEUP_REPORT.md`: a ranked sweep, the winning model, a
real before/after number, and the exact steps to put it in the app.

## The loop the model runs
`analyze -> classify -> propose`. The model judges; **the app decides and acts**
(nothing runs without the user's approval). Fields like "which action is allowed
to auto-run" and "does this need admin" are the app's policy table, not the
model's job.

## Files
```
contract.py          Single source of truth: enums, SYSTEM_PROMPT, build_messages,
                     OUTPUT_JSON_SCHEMA (what you hand Ollama's `format`), validators.
                     Import this on BOTH sides so training and the app never drift.
generate_dataset.py  Scenario generator. Labels correct by construction.
data/*.jsonl         Generated train / eval_dev / eval_test (already built).
evaluate.py          Honest metrics (threat acc, cry-wolf FP rate, json-valid, composite).
training_modal.py    One Modal job: load -> LoRA -> eval -> result.json (+GGUF for winner).
run_sweep.py         Orchestrator + watchdog: smoke-gate, parallel sweep, finalize, report.
make_report.py       Writes WAKEUP_REPORT.md.
selftest.py          No-GPU sanity check of the whole pipeline. Run it first.
```

## The INPUT contract (hand this to Luke)
Every scanner emits one finding in this shape; the model is trained on exactly
this. Fields marked \* are required; everything else is best-effort, and the
model is trained with optional fields missing so partial scanners still work.
```
{ "finding_id"*, "source"* (processes|storage|network|backups),
  "os"* (windows|macos|linux), "mode" (manual|scheduled|always_active),
  "finding": { ...source-specific... } }
```
- **processes**: name\*, pid\*, exe_path, cmdline, parent_name, user, cpu_pct,
  cpu_high_minutes, mem_mb, signed, signer, remote_endpoints[], listening, is_new
- **storage**: kind\* (file|burst). file: path\*, event\*, extension, size_bytes,
  entropy/avg_entropy, is_executable, origin_url, written_by, is_new. burst:
  event\*, count\*, window_sec, dirs_affected, ext_changes[], avg_entropy, note_files[]
- **network**: ip\*, mac, vendor, hostname, is_gateway, is_this_device, is_new,
  open_ports[{port,service}], exposed_to, bound_process, shares_mac_with[]
- **backups**: backup_path\*, files_total, changed, missing, added, changed_exts[],
  avg_entropy_changed, last_backup_hours, expected_interval_hours

The OUTPUT shape is `contract.OUTPUT_JSON_SCHEMA`. In the app, pass it as Ollama's
`format` and set `temperature 0` so every response parses.

## Run order
```
python selftest.py                     # no GPU: proves data/schema/eval/report are consistent
modal deploy training_modal.py         # deploy run_job so spawned jobs detach from this laptop
caffeinate -is python run_sweep.py     # macOS: don't sleep while the orchestrator polls
```
`run_sweep.py` does, in order: a ~10-min **smoke test** (and STOPS if it fails,
so a broken API never burns the sweep budget), then the 6-run sweep + 2
baselines in parallel, then 3 seeded re-runs of the winner with GGUF export,
then the report.

## Prereqs (do these before launching)
1. `pip install modal` and `modal token new` (already done; auth in `~/.modal.toml`).
2. Accept the **Gemma license** on Hugging Face for the model you use, then create
   a Modal secret with a token that has access:
   `modal secret create huggingface HF_TOKEN=hf_xxx`
   (The models are gated; without this the download 401s. The smoke test fails
   fast and tells you if it's missing.)
3. The repo is **public**: never commit `.env`, tokens, or the Funnel URL.

## Why it survives the night
- Jobs run on Modal (deployed), so they keep going even if the Mac sleeps.
- State is saved after every change. Re-running `run_sweep.py` **reconnects** to
  in-flight jobs instead of relaunching them, so Ctrl-C or a dead session is safe.
  If anything stops early, just run `python run_sweep.py` again in the morning.
- Watchdog: per-job deadline, bounded retries (OOM -> retry in 4-bit),
  transient-vs-code-bug handling, a circuit breaker if most jobs fail the same
  way, and a cost cap (`COST_CAP_USD`, default $25; real cost is a few dollars).

## VERIFY lines
Gemma 4 and current Unsloth post-date the pipeline author's training cutoff, so
the Unsloth/Gemma-4 calls in `training_modal.py` are marked `# VERIFY`. The Modal
SDK calls in `run_sweep.py` were checked against modal 1.6.1 and are fine. The
smoke test is what proves the Unsloth path before the sweep spends anything; if
smoke fails, fix the VERIFY lines against current Unsloth docs and re-run.
