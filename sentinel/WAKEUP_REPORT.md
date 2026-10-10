# Sentinel fine-tune: wake-up report

_Generated 2026-10-10T11:17:21Z_

- Started: 2026-10-10T08:16:36.791251+00:00
- Ended: 2026-10-10T11:17:21.221925+00:00
- Reached phase: **report**
- Jobs: 11 done, 1 failed
- Estimated GPU cost: **$9.48**

## TL;DR
**Winner config:** `sweep_e4b_lr0.0002`  (`gemma-4-E4B-it`, lr 0.0002, 3 epochs, LoRA r16)
**Seed variance (test tt_acc across 3 seeds):** 99.6% ± 0.6%
**Best seed:** `final_it_s0`  test tt_acc 98.8%, test FP 0.0%, hard-neg FP 0.0%, json ok 100.0%
**GGUF (on Modal volume):** `/vol/gguf/final_it_s0_gguf`
**Before vs after (base_e4b -> winner):** test tt_acc 27.5% -> 98.8%  (**+71.2 pts**)

## Sweep results (ranked by composite = tt_acc - 0.5*FP)
| run | base | lr | dev tt_acc | dev FP | test tt_acc | test hard-FP | json ok | composite | sec |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| sweep_e4b_lr0.0002 | gemma-4-E4B-it | 0.0002 | 100.0% | 0.0% | 98.8% | 0.0% | 100.0% | 1.0 | 4074.6 |
| sweep_e4b_lr0.0001 | gemma-4-E4B-it | 0.0001 | 100.0% | 0.0% | 100.0% | 0.0% | 100.0% | 1.0 | 4210.9 |
| sweep_e2b_lr0.0002 | gemma-4-E2B-it | 0.0002 | 100.0% | 0.0% | 100.0% | 0.0% | 100.0% | 1.0 | 3294.4 |
| sweep_e2b_lr0.0001 | gemma-4-E2B-it | 0.0001 | 100.0% | 0.0% | 98.8% | 0.0% | 100.0% | 1.0 | 3087.6 |
| sweep_e4b_lr5e-05 | gemma-4-E4B-it | 5e-05 | 98.8% | 0.0% | 100.0% | 0.0% | 100.0% | 0.9875 | 3073.0 |

## Baselines (before fine-tuning)
- **base_e4b** (no fine-tune): test tt_acc 27.5%, test FP 4.5%, json ok 30.0%
- **base_e2b** (no fine-tune): test tt_acc 56.2%, test FP 36.4%, json ok 96.2%

## Red flags
- 1 job(s) failed: sweep_e2b_lr5e-05. See orchestrator.log.
- `smoke` json-valid 66.7% (<95%): pass OUTPUT_JSON_SCHEMA in Ollama's `format` field to force valid JSON.
- `base_e4b` json-valid 30.0% (<95%): pass OUTPUT_JSON_SCHEMA in Ollama's `format` field to force valid JSON.

## Do this next: put the winner in the app
1. Pull the winning GGUF off the Modal volume to the PC that runs Ollama:
   ```
   modal volume get sentinel-vol gguf/final_it_s0_gguf ./sentinel-model
   ls ./sentinel-model     # note the *.Q4_K_M.gguf file name
   ```
2. Create an Ollama Modelfile (`Modelfile.sentinel`). The system prompt is baked
   in so it matches training exactly:
   ```
   FROM ./sentinel-model/<the Q4_K_M file>
   TEMPLATE """{{- range $i, $_ := .Messages }}
{{- $last := eq (len (slice $.Messages $i)) 1 }}
<|turn>{{ .Role }}
{{ .Content }}{{ if not $last }}<turn|>
{{ end }}
{{- end }}<turn|>
<|turn>model
"""
   PARAMETER stop "<turn|>"
   PARAMETER temperature 0
   PARAMETER num_ctx 2048
   SYSTEM """You are Sentinel, a local device-security triage engine. You receive ONE finding from a system scanner and judge only that finding. Reply with ONLY a single JSON object and no other text.

Schema:
  finding_id: copy the id from the input exactly.
  evidence: 2-3 short strings, each citing one specific signal from the input that drove your judgement.
  threat_type: one of ['arp_spoofing', 'backdoor_port', 'backup_deleted', 'backup_encrypted', 'backup_tampering', 'cryptominer', 'exposed_service', 'malicious_download', 'malicious_script', 'masquerading', 'mass_deletion', 'none', 'other_suspicious', 'ransomware', 'remote_access_tool', 'rogue_device', 'stale_backup', 'system_file_tampering'].
  severity: one of ['none', 'low', 'medium', 'high', 'critical'].
  confidence: one of ['low', 'medium', 'high'].
  actions: 0 to 2 proposed actions from ['none', 'monitor', 'kill_process', 'quarantine_file', 'disconnect_network', 'close_port', 'restore_backup', 'run_backup', 'guide_user'].
  explanation: ONE plain-English sentence a non-technical person understands. No jargon.
  escalate: boolean; true when you are unsure, or when severity is medium or higher but confidence is low.

Rules:
- Normal, expected activity is threat_type "none", severity "none", actions [] or ["monitor"].
- High resource use, many file changes, open ports, or new devices are NOT automatically threats. Weigh who did it, where it ran, and whether it is signed/known before flagging.
- Use only values present in the input. Never invent paths, pids, or ids.
- You propose actions only. Nothing runs without the user's approval, so never imply an action has already happened."""
   ```
3. Register it with Ollama on the PC:
   ```
   ollama create sentinel -f Modelfile.sentinel
   ollama run sentinel "{...a test finding...}"
   ```
4. Point the app at it: set `OLLAMA_MODEL=sentinel` in the repo `.env`
   (the Tailscale Funnel URL stays the same).
5. In the backend's Ollama call, send `format` = the JSON schema and
   `options.temperature = 0` so every response parses. The schema is
   `contract.OUTPUT_JSON_SCHEMA`; keep the one source of truth.
6. Verify end-to-end from the Mac:
   ```
   curl "$OLLAMA_URL/api/chat" -d '{
     "model":"sentinel","stream":false,
     "messages":[{"role":"user","content":"<paste one finding JSON>"}]
   }'
   ```
   If judgements look off, re-read WAKEUP_REPORT red flags before retraining.

Winner finalize run: `final_it_s0`


---
_Metric notes: `tt_acc` = exact threat-type match; `FP` = benign findings wrongly
flagged (the cry-wolf rate); `hard-FP` = FP on the deliberately tricky benign
cases; `json ok` = fraction parseable before Ollama's `format` is even applied._
