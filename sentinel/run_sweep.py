"""
Overnight orchestrator + watchdog for the Sentinel fine-tune sweep.

What it does, in order, unattended:
  1. SMOKE  - one tiny job. If it fails, STOP (don't burn money on a broken path).
  2. SWEEP  - 6 LoRA runs {E4B,E2B} x {5e-5,1e-4,2e-4} + 2 base-model baselines,
              all in parallel on Modal.
  3. FINALIZE - re-run the winning config at 3 seeds with GGUF export, for a real
              variance number and a shippable model.
  4. REPORT - write WAKEUP_REPORT.md: ranked table, winner, before/after vs base,
              and the exact steps to load the model into Ollama and point the app at it.

Why it survives the night:
  - Jobs run on Modal (deployed), so they keep going even if this laptop sleeps.
  - State is saved to run_state.json after every change; re-running this script
    RECONNECTS to in-flight jobs instead of relaunching them. Safe to Ctrl-C.
  - Watchdog: per-job deadline, bounded retries, transient-vs-deterministic
    failure handling, a circuit breaker if most jobs fail the same way, and a
    cost cap.

Prereqs (the mega-prompt handles these):
  modal deploy training_modal.py        # deploy run_job so spawn() detaches
  caffeinate -is python run_sweep.py     # macOS: don't sleep while polling

VERIFY: lines touching the Modal spawn/poll API are marked; the smoke phase
surfaces any drift before the sweep spends anything.
"""

from __future__ import annotations

import json
import math
import os
import time
from datetime import datetime, timezone

import modal

APP_NAME = "sentinel-sft"
STATE_PATH = "run_state.json"
LOG_PATH = "orchestrator.log"

E4B = "unsloth/gemma-4-E4B-it"   # VERIFY repo id
E2B = "unsloth/gemma-4-E2B-it"   # VERIFY repo id

POLL_SECS = 20
JOB_DEADLINE_SECS = 125 * 60      # kill+retry a job that runs longer than this (> Modal timeout)
MAX_ATTEMPTS = 2                  # per run (1 retry) for transient failures
COST_CAP_USD = 25.0               # generous guardrail; real cost ~ a few dollars
GPU_RATE_USD_PER_HR = 0.80        # VERIFY current L4 price; only used for the cap

# --- Modal exception taxonomy (verified against modal 1.6.1) ------------------
# Key subtlety: modal.exception.TimeoutError is NOT builtin TimeoutError, and a
# still-running job polled with get(timeout=0) raises the modal one. A job that
# blew its own `timeout=` raises FunctionTimeoutError (a SUBCLASS of the modal
# TimeoutError), which is terminal, so we must test it FIRST.
import modal.exception as _mex

_POLL_TIMEOUT = getattr(_mex, "TimeoutError", TimeoutError)          # "still running"
_FN_TIMEOUT = getattr(_mex, "FunctionTimeoutError", None)            # terminal
_OUTPUT_EXPIRED = getattr(_mex, "OutputExpiredError", None)          # terminal

TRANSIENT_HINTS = ("out of memory", "cuda", "oom", "nccl", "connection",
                   "timeout", "preempt", "429", "unavailable", "reset")


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

def now() -> float:
    return time.time()


def log(msg: str) -> None:
    line = f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}  {msg}"
    print(line, flush=True)
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def load_state() -> dict:
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH) as fh:
            return json.load(fh)
    return {"phase": "smoke", "runs": {}, "winner": None,
            "started": datetime.now(timezone.utc).isoformat()}


def save_state(st: dict) -> None:
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(st, fh, indent=2)
    os.replace(tmp, STATE_PATH)


# ---------------------------------------------------------------------------
# Configs
# ---------------------------------------------------------------------------

def sweep_configs() -> list[dict]:
    cfgs = []
    for base, tag in [(E4B, "e4b"), (E2B, "e2b")]:
        for lr in (5e-5, 1e-4, 2e-4):
            cfgs.append({
                "run_name": f"sweep_{tag}_lr{lr:g}",
                "base_model": base, "lr": lr, "seed": 0, "epochs": 3,
                "load_in_4bit": False, "train": True, "export_gguf": False,
            })
    # baselines: no training, eval only (before-numbers)
    cfgs.append({"run_name": "base_e4b", "base_model": E4B, "lr": 0, "seed": 0,
                 "epochs": 0, "train": False, "export_gguf": False})
    cfgs.append({"run_name": "base_e2b", "base_model": E2B, "lr": 0, "seed": 0,
                 "epochs": 0, "train": False, "export_gguf": False})
    return cfgs


def finalize_configs(winner_cfg: dict) -> list[dict]:
    out = []
    for seed in (0, 1, 2):
        c = dict(winner_cfg)
        c["run_name"] = f"final_{winner_cfg['base_model'].split('-')[-1].lower()}_s{seed}"
        c["seed"] = seed
        c["export_gguf"] = True
        c["train"] = True
        out.append(c)
    return out


# ---------------------------------------------------------------------------
# Spawn / poll
# ---------------------------------------------------------------------------

def get_fn():
    # VERIFY: looks up the deployed run_job. If this raises, run
    # `modal deploy training_modal.py` first.
    return modal.Function.from_name(APP_NAME, "run_job")


def poll(object_id: str):
    """Return ('done', result) | ('running', None) | ('error', exc)."""
    try:
        fc = modal.FunctionCall.from_id(object_id)
        res = fc.get(timeout=0)
        return "done", res
    except Exception as e:
        # order matters: FunctionTimeoutError subclasses the poll TimeoutError.
        if _FN_TIMEOUT and isinstance(e, _FN_TIMEOUT):
            return "error", e           # job exceeded its own timeout -> terminal
        if _OUTPUT_EXPIRED and isinstance(e, _OUTPUT_EXPIRED):
            return "error", e
        if isinstance(e, _POLL_TIMEOUT) or isinstance(e, TimeoutError):
            return "running", None      # not ready yet -> still running
        return "error", e               # remote job raised -> real failure


def cancel(object_id: str) -> None:
    try:
        modal.FunctionCall.from_id(object_id).cancel()  # VERIFY cancel API
    except Exception as e:
        log(f"  (cancel failed for {object_id}: {e})")


def is_transient(err: str) -> bool:
    e = err.lower()
    return any(h in e for h in TRANSIENT_HINTS)


def est_cost(st: dict) -> float:
    secs = 0.0
    for r in st["runs"].values():
        if r.get("start"):
            end = r.get("end") or now()
            secs += max(0.0, end - r["start"])
    return (secs / 3600.0) * GPU_RATE_USD_PER_HR


# ---------------------------------------------------------------------------
# Phase runner
# ---------------------------------------------------------------------------

def run_phase(st: dict, phase: str, configs: list[dict], gate: bool = False) -> bool:
    """Spawn+watch all configs. Returns True if the phase is acceptable to
    proceed from. Idempotent/resumable."""
    fn = get_fn()
    names = [c["run_name"] for c in configs]
    log(f"=== PHASE {phase}: {len(configs)} jobs: {names}")

    # Spawn any not yet launched (resume-safe).
    for c in configs:
        r = st["runs"].get(c["run_name"])
        if r and r.get("object_id") and r.get("status") in ("running", "done", "failed"):
            continue
        if est_cost(st) > COST_CAP_USD:
            log(f"  COST CAP hit (${est_cost(st):.2f}); not spawning {c['run_name']}")
            st["runs"].setdefault(c["run_name"], {})["status"] = "skipped_cost"
            continue
        try:
            fc = fn.spawn(c)                           # VERIFY spawn API
            st["runs"][c["run_name"]] = {
                "cfg": c, "object_id": fc.object_id, "status": "running",
                "start": now(), "attempts": r.get("attempts", 0) + 1 if r else 1,
            }
            log(f"  spawned {c['run_name']} ({fc.object_id})")
        except Exception as e:
            log(f"  SPAWN FAILED {c['run_name']}: {e}")
            st["runs"][c["run_name"]] = {"cfg": c, "status": "failed", "error": str(e),
                                         "attempts": (r or {}).get("attempts", 0) + 1}
        save_state(st)

    # Poll until all terminal.
    fail_sigs: dict[str, int] = {}
    while True:
        pending = [c for c in configs
                   if st["runs"].get(c["run_name"], {}).get("status") == "running"]
        if not pending:
            break

        for c in pending:
            name = c["run_name"]
            r = st["runs"][name]
            status, payload = poll(r["object_id"])

            if status == "done":
                r["status"] = "done"
                r["end"] = now()
                r["summary"] = _summarize(payload)
                log(f"  DONE {name}: {r['summary'].get('headline')}")
            elif status == "running":
                if now() - r["start"] > JOB_DEADLINE_SECS:
                    log(f"  DEADLINE {name} exceeded; cancelling")
                    cancel(r["object_id"])
                    _handle_failure(st, c, r, "job deadline exceeded (stalled)")
            else:  # error
                _handle_failure(st, c, r, str(payload))
                # only terminal failures count toward the breaker (a retried OOM doesn't)
                if st["runs"][name].get("status") == "failed":
                    sig = type(payload).__name__
                    fail_sigs[sig] = fail_sigs.get(sig, 0) + 1
            save_state(st)

        # Circuit breaker: majority failing the same way -> stop the night early.
        done_or_failed = [c for c in configs
                          if st["runs"].get(c["run_name"], {}).get("status")
                          in ("done", "failed", "skipped_cost")]
        worst = max(fail_sigs.values()) if fail_sigs else 0
        if worst >= math.ceil(len(configs) / 2):
            log(f"  CIRCUIT BREAKER: {worst}/{len(configs)} jobs failed with the "
                f"same error. Aborting phase to avoid wasting spend.")
            return False
        if est_cost(st) > COST_CAP_USD:
            log(f"  COST CAP hit (${est_cost(st):.2f}); stopping polling.")
            break

        time.sleep(POLL_SECS)

    oks = [c for c in configs if st["runs"][c["run_name"]].get("status") == "done"]
    log(f"=== PHASE {phase} complete: {len(oks)}/{len(configs)} ok")

    if gate:
        if not oks:
            log("  SMOKE did not pass. Fix the VERIFY lines in training_modal.py "
                "and re-run. NOT launching the sweep.")
            return False
        smoke = st["runs"][configs[0]["run_name"]]["summary"]
        if (smoke.get("dev_json_valid") or 0) <= 0:
            log("  SMOKE produced no parseable JSON. Check the prompt/template "
                "(VERIFY lines). NOT launching the sweep.")
            return False
    return True


def _handle_failure(st: dict, c: dict, r: dict, err: str) -> None:
    attempts = r.get("attempts", 1)
    if attempts < MAX_ATTEMPTS and is_transient(err):
        log(f"  RETRY {c['run_name']} (attempt {attempts+1}) after transient: {err[:120]}")
        retry = dict(c)
        if "memory" in err.lower() or "oom" in err.lower():
            retry["load_in_4bit"] = True  # shrink footprint on OOM
        r["status"] = "pending"
        r.pop("object_id", None)
        # respawn on next spawn sweep by clearing object_id + updating cfg
        st["runs"][c["run_name"]] = {"cfg": retry, "status": "pending",
                                     "attempts": attempts}
        # immediate respawn
        try:
            fc = get_fn().spawn(retry)
            st["runs"][c["run_name"]] = {"cfg": retry, "object_id": fc.object_id,
                                         "status": "running", "start": now(),
                                         "attempts": attempts + 1}
            log(f"    respawned {c['run_name']} ({fc.object_id})")
        except Exception as e:
            st["runs"][c["run_name"]] = {"cfg": retry, "status": "failed",
                                         "error": str(e), "attempts": attempts + 1}
    else:
        r["status"] = "failed"
        r["error"] = err
        r["end"] = now()
        log(f"  FAILED {c['run_name']}: {err[:160]}")


def _summarize(res: dict) -> dict:
    if not isinstance(res, dict):
        return {"headline": "no result payload"}
    dev = res.get("dev", {}) or {}
    test = res.get("test", {}) or {}
    return {
        "headline": f"dev tt_acc={dev.get('threat_type_acc')} fp={dev.get('benign_fp_rate')}",
        "dev_tt_acc": dev.get("threat_type_acc"),
        "dev_fp": dev.get("benign_fp_rate"),
        "dev_json_valid": dev.get("json_valid_rate"),
        "dev_recall": dev.get("threat_recall"),
        "test_tt_acc": test.get("threat_type_acc"),
        "test_fp": test.get("benign_fp_rate"),
        "test_hard_fp": test.get("hard_neg_fp_rate"),
        "test_json_valid": test.get("json_valid_rate"),
        "composite": dev.get("composite"),
        "seconds": res.get("seconds"),
        "gguf": res.get("gguf"),
    }


def pick_winner(st: dict) -> dict | None:
    cands = []
    for name, r in st["runs"].items():
        if not name.startswith("sweep_") or r.get("status") != "done":
            continue
        s = r["summary"]
        if s.get("composite") is None:
            continue
        # rank by composite, then lower benign FP, then higher json-valid
        cands.append((s["composite"], -(s.get("dev_fp") or 0),
                      s.get("dev_json_valid") or 0, name, r["cfg"]))
    if not cands:
        return None
    cands.sort(reverse=True)
    winner_name, winner_cfg = cands[0][3], cands[0][4]
    st["winner"] = {"run_name": winner_name, "cfg": winner_cfg}
    log(f"WINNER: {winner_name}  composite={cands[0][0]}")
    return st["winner"]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    st = load_state()
    log(f"orchestrator start (phase={st['phase']}, known runs={len(st['runs'])})")

    if st["phase"] == "smoke":
        from training_modal import run_job  # ensure module imports (local check)  # noqa
        ok = run_phase(st, "smoke", [{
            "run_name": "smoke", "base_model": E2B, "lr": 2e-4, "seed": 0,
            "epochs": 1, "load_in_4bit": True, "train": True,
            "export_gguf": True, "max_train_rows": 24, "max_eval_rows": 6,
        }], gate=True)
        if not ok:
            log("Stopping at smoke. See orchestrator.log.")
            return
        st["phase"] = "sweep"
        save_state(st)

    if st["phase"] == "sweep":
        ok = run_phase(st, "sweep", sweep_configs())
        if not ok:
            log("Sweep aborted (circuit breaker). Writing partial report.")
            _finish(st)
            return
        if not pick_winner(st):
            log("No winner (all sweep runs failed). Writing partial report.")
            _finish(st)
            return
        st["phase"] = "finalize"
        save_state(st)

    if st["phase"] == "finalize":
        winner = st.get("winner")
        if winner:
            run_phase(st, "finalize", finalize_configs(winner["cfg"]))
        st["phase"] = "report"
        save_state(st)

    _finish(st)


def _finish(st: dict):
    st["ended"] = datetime.now(timezone.utc).isoformat()
    st["est_cost_usd"] = round(est_cost(st), 2)
    save_state(st)
    try:
        import make_report
        make_report.build(st, "WAKEUP_REPORT.md")
        log("wrote WAKEUP_REPORT.md")
    except Exception as e:
        log(f"report generation failed: {e}")
    log(f"DONE. est cost ${st['est_cost_usd']}. Read WAKEUP_REPORT.md")


if __name__ == "__main__":
    main()
