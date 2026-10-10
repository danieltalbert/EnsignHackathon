Paste everything below into Claude Code (in the repo, VS Code terminal).

---

You are running an overnight, unattended fine-tuning job for our hackathon
security tool. I am going to sleep. Your goal: wake me up to a ranked set of
results and a clear path to merge the winning model into the app. Work
autonomously and do NOT stop to ask me questions; make the reasonable call,
write down what you decided, and keep going. The one exception is a hard blocker
you cannot resolve (see STOP conditions).

## What's already here
I've added a folder `sentinel/` with a complete, self-tested pipeline:
dataset (already generated), a Modal trainer, an eval harness, an orchestrator
with a watchdog, and a report generator. Read `sentinel/README.md` first, then
skim `sentinel/contract.py`, `sentinel/training_modal.py`, and
`sentinel/run_sweep.py`. Do not rewrite these; your job is to get them running
and fix only what's broken.

## Context you must respect
- The product runs on the user's own machine; the model is served remotely from
  my PC (Ollama + Gemma 4 over Tailscale Funnel). Nothing about that changes here.
- The model's only job is: read ONE scanner finding, return the strict-JSON
  judgement defined in `contract.py`. The app decides/acts; the model only judges.
- The repo is PUBLIC. Never commit `.env`, API tokens, or the Funnel URL. Never
  paste any secret into a file or a commit.
- Modal auth is already set in `~/.modal.toml`. Do not touch it.

## Do this, in order
1. `cd sentinel && python selftest.py`. It needs no GPU. If it fails, fix the
   data/contract issue it reports before anything else.
2. Confirm the Modal Hugging Face secret exists: `modal secret list` should show
   `huggingface`. If it does NOT, STOP and tell me (I have to create it with my
   HF token and accept the Gemma license; you can't do that without my token).
3. The Unsloth/Gemma-4 calls in `training_modal.py` are marked `# VERIFY` because
   they post-date the author's knowledge cutoff. Quickly check them against
   current Unsloth Gemma-4 docs and fix any obvious drift (loader name, chat
   template string, GGUF export call). The Modal SDK calls are already verified
   against modal 1.6.1; leave them.
4. `modal deploy training_modal.py`.
5. Launch the orchestrator in the background so it survives this session, under
   caffeinate so the Mac doesn't sleep:
   `nohup caffeinate -is python run_sweep.py > run.out 2>&1 &`
6. Watch the SMOKE phase only (first ~10 min): tail `orchestrator.log`. The
   orchestrator runs one tiny job first and refuses to launch the sweep if it
   fails. If smoke fails, read the error, fix the relevant `# VERIFY` line, and
   re-run `python run_sweep.py` (it resumes). If smoke fails twice for the SAME
   reason, STOP and write the blocker to `BLOCKED.md` (do not keep retrying).
7. Once smoke passes and the sweep is spawning, stop babysitting. Check back by
   reading `orchestrator.log` / `run_state.json` periodically until
   `run_state.json` shows `"phase": "report"`.
8. When done, read `WAKEUP_REPORT.md` and write me a 5-line `SUMMARY_FOR_DANIEL.md`:
   the winning model + its before/after number, the estimated cost, any red
   flags, and whether the GGUF exported cleanly. Do NOT flip anything in the app
   to the new model, that's a decision for me in the morning; just stage it
   (the report has the exact Ollama Modelfile + `.env` change).

## STOP conditions (write BLOCKED.md and stop, don't loop)
- The `huggingface` Modal secret is missing.
- Smoke fails twice with the same error after a fix attempt.
- The circuit breaker trips (most jobs failing the same way) — the report will
  still be written; summarize what broke.

## Notes
- If this session ends before the run finishes, that's fine: the jobs are on
  Modal and `run_sweep.py` is resumable. I can run it again in the morning to
  finish and regenerate the report.
- Keep a running note of decisions you make in `NIGHT_LOG.md` so I can see what
  happened while I slept.
