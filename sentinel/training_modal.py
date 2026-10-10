"""
Modal training + eval for Sentinel (Gemma 4 E4B / E2B, Unsloth LoRA).

One function `run_job` does everything for a single config: load base model,
(optionally) LoRA fine-tune, evaluate on dev+test, write result.json to the
shared Volume, and (for the winner only) export GGUF. The orchestrator
(run_sweep.py) spawns many of these in parallel.

IMPORTANT — VERSION NOTE
Gemma 4 and current Unsloth post-date this script author's knowledge cutoff
(Jan 2026). Every line that touches the Unsloth / Gemma-4 / Modal API is marked
`# VERIFY`. The smoke-test phase in run_sweep.py runs ONE tiny job first so any
API drift surfaces in ~10 minutes, before the real sweep spends money. If the
smoke job fails, fix the VERIFY lines against current docs, then re-run; do not
launch the sweep until smoke passes.

Local deps: `pip install modal`. Auth already in ~/.modal.toml.
Secrets: a Modal secret named "huggingface" with HF_TOKEN that has accepted the
Gemma license on Hugging Face (the models are gated — without this, download
401s).
"""

from __future__ import annotations

import json
import os

import modal

APP_NAME = "sentinel-sft"
VOL_NAME = "sentinel-vol"
CACHE_NAME = "sentinel-hf-cache"

app = modal.App(APP_NAME)

# Persistent volumes: one for results/adapters/gguf, one to cache base weights
# so N parallel containers don't each re-download Gemma.
vol = modal.Volume.from_name(VOL_NAME, create_if_missing=True)
cache = modal.Volume.from_name(CACHE_NAME, create_if_missing=True)

# VERIFY: pin versions to whatever the smoke test proves working. Unsloth moves
# fast; these are starting points, not guarantees.
image = (
    modal.Image.debian_slim(python_version="3.11")
    # build tools so Unsloth can fall back to compiling llama.cpp for GGUF export
    .apt_install("git", "build-essential", "cmake", "curl", "libcurl4-openssl-dev")
    .pip_install(
        "unsloth==2026.10.3",  # latest on PyPI 2026-10-10; Gemma-4 templates present
        "unsloth_zoo==2026.10.3",
        "trl",
        "transformers",
        "datasets",
        "accelerate",
        "bitsandbytes",
        "sentencepiece",
        "protobuf",
    )
    # add_local_dir must be last. VERIFY: on older Modal use
    # mounts=[modal.Mount.from_local_dir(".", remote_path="/root/sentinel")].
    .add_local_dir(
        ".", "/root/sentinel",
        ignore=["__pycache__", "*.pyc", ".git", "*.zip"],
    )
)

HF_CACHE_DIR = "/cache/hf"


def _load_rows(path: str):
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


@app.function(
    image=image,
    gpu="L4",                 # 24GB; fits E4B 16-bit LoRA (~17GB). VERIFY cost/avail.
    volumes={"/vol": vol, "/cache": cache},
    # Gemma 4 is Apache-2.0 and ungated on HF (checked 2026-10-10), so no HF token
    # secret is needed. Re-add secrets=[modal.Secret.from_name("huggingface")] if
    # you switch to a gated base model.
    timeout=60 * 120,         # hard per-job ceiling; watchdog also enforces one.
    retries=0,                # orchestrator decides retries (transient vs code bug).
)
def run_job(cfg: dict) -> dict:
    """cfg keys: run_name, base_model, lr, seed, epochs, load_in_4bit, export_gguf, train(bool)."""
    import sys, time, random
    sys.path.insert(0, "/root/sentinel")
    os.chdir("/root/sentinel")
    os.environ["HF_HOME"] = HF_CACHE_DIR

    import torch  # noqa
    from contract import build_messages
    import evaluate as ev

    run_name = cfg["run_name"]
    base_model = cfg["base_model"]
    do_train = cfg.get("train", True)
    t0 = time.time()
    log = []

    def say(m):
        line = f"[{run_name}] {m}"
        print(line, flush=True)
        log.append(line)

    random.seed(cfg.get("seed", 0))
    torch.manual_seed(cfg.get("seed", 0))

    say(f"loading base {base_model} (4bit={cfg.get('load_in_4bit', False)})")
    # VERIFY: Gemma-4 loader. From Unsloth Gemma-4 docs/notebooks.
    from unsloth import FastModel
    model, tokenizer = FastModel.from_pretrained(
        model_name=base_model,
        max_seq_length=2048,
        load_in_4bit=cfg.get("load_in_4bit", False),
        dtype=None,
    )

    # VERIFY: standard (non-thinking) Gemma-4 chat template.
    from unsloth.chat_templates import get_chat_template
    tokenizer = get_chat_template(tokenizer, chat_template="gemma-4")
    # E2B/E4B are multimodal and load as a processor; use its text tokenizer for
    # plain-text templating/encoding (the template is set on both).
    from transformers import ProcessorMixin
    text_tok = tokenizer.tokenizer if isinstance(tokenizer, ProcessorMixin) else tokenizer

    if do_train:
        say("attaching LoRA adapter")
        model = FastModel.get_peft_model(
            model,
            r=cfg.get("lora_r", 16),
            lora_alpha=cfg.get("lora_alpha", 16),
            lora_dropout=0.0,
            finetune_vision_layers=False,   # text-only task: keep LoRA off the vision tower
            finetune_language_layers=True,
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                            "gate_proj", "up_proj", "down_proj"],
            use_gradient_checkpointing="unsloth",
            random_state=cfg.get("seed", 0),
        )

        # Build the training texts: system+user -> assistant(target JSON).
        train_rows = _load_rows("data/train.jsonl")
        if cfg.get("max_train_rows"):
            train_rows = train_rows[: cfg["max_train_rows"]]  # smoke test uses a tiny slice

        def to_text(row):
            msgs = build_messages(row["input"])
            msgs = msgs + [{"role": "assistant",
                            "content": json.dumps(row["target"], ensure_ascii=False)}]
            # VERIFY: apply_chat_template signature for Gemma-4.
            return text_tok.apply_chat_template(msgs, tokenize=False,
                                                add_generation_prompt=False)

        from datasets import Dataset
        ds = Dataset.from_list([{"text": to_text(r)} for r in train_rows])

        from trl import SFTTrainer, SFTConfig
        trainer = SFTTrainer(
            model=model,
            tokenizer=tokenizer,
            train_dataset=ds,
            args=SFTConfig(
                dataset_text_field="text",
                per_device_train_batch_size=cfg.get("batch_size", 2),
                gradient_accumulation_steps=cfg.get("grad_accum", 4),
                warmup_steps=0.05,   # transformers 5.x: float <1 = ratio (warmup_ratio removed)
                num_train_epochs=cfg.get("epochs", 3),
                learning_rate=cfg["lr"],
                logging_steps=10,
                optim="adamw_8bit",
                weight_decay=0.01,
                lr_scheduler_type="linear",
                seed=cfg.get("seed", 0),
                output_dir=f"/vol/checkpoints/{run_name}",
                bf16=True,
                report_to="none",
            ),
        )
        # VERIFY: train only on the assistant turn so the model learns the JSON,
        # not the prompt. Gemma-4 turn markers.
        from unsloth.chat_templates import train_on_responses_only
        try:
            trainer = train_on_responses_only(
                trainer,
                instruction_part="<|turn>user\n",   # Gemma-4 markers (not Gemma-3's <start_of_turn>)
                response_part="<|turn>model\n",
            )
        except Exception as e:
            say(f"WARN train_on_responses_only failed ({e}); training on full text")
        say("training...")
        trainer.train()
        say(f"training done in {time.time()-t0:.0f}s")

    # ---- Inference for eval ------------------------------------------------
    # VERIFY: Unsloth fast inference enable.
    try:
        FastModel.for_inference(model)
    except Exception as e:
        say(f"WARN for_inference unavailable ({e})")

    end_ids = [i for i in {text_tok.convert_tokens_to_ids("<turn|>"), text_tok.eos_token_id}
               if isinstance(i, int)]

    def generate(finding: dict) -> str:
        msgs = build_messages(finding)
        prompt = text_tok.apply_chat_template(
            msgs, tokenize=False, add_generation_prompt=True)
        # Unsloth's Gemma template already emits <bos>; don't add a second one
        # (training tokenizes the same way, so train and eval match).
        inputs = text_tok(prompt, return_tensors="pt",
                          add_special_tokens=not prompt.startswith(text_tok.bos_token or "<bos>")
                          ).to(model.device)
        out = model.generate(**inputs, max_new_tokens=320, do_sample=False,
                             temperature=0.0, use_cache=True,
                             eos_token_id=end_ids)  # stop at Gemma-4 end-of-turn
        text = text_tok.decode(out[0][inputs["input_ids"].shape[1]:],
                               skip_special_tokens=True)
        return text

    def eval_split(path: str) -> dict:
        rows = _load_rows(path)
        if cfg.get("max_eval_rows"):
            rows = rows[: cfg["max_eval_rows"]]  # smoke test only
        preds = []
        t_eval = time.time()
        for r in rows:
            raw = generate(r["input"])
            preds.append({"finding_id": r["target"]["finding_id"], "raw": raw})
        # keep raw outputs on the volume so red flags can be inspected later
        split = os.path.basename(path).replace(".jsonl", "")
        os.makedirs("/vol/preds", exist_ok=True)
        with open(f"/vol/preds/{run_name}_{split}.jsonl", "w", encoding="utf-8") as fh:
            for p in preds:
                fh.write(json.dumps(p, ensure_ascii=False) + "\n")
        say(f"{split}: {len(rows)} rows in {time.time()-t_eval:.0f}s; sample: {preds[0]['raw'][:200]!r}")
        return ev.score(rows, preds)

    say("evaluating dev")
    dev = eval_split("data/eval_dev.jsonl")
    say(f"dev: tt_acc={dev['threat_type_acc']} fp={dev['benign_fp_rate']} json={dev['json_valid_rate']}")
    say("evaluating test")
    test = eval_split("data/eval_test.jsonl")
    say(f"test: tt_acc={test['threat_type_acc']} fp={test['benign_fp_rate']}")

    result = {
        "run_name": run_name, "config": cfg,
        "dev": dev, "test": test,
        "seconds": round(time.time() - t0, 1),
        "trained": do_train, "status": "ok",
        "log": log,
    }

    os.makedirs("/vol/results", exist_ok=True)
    with open(f"/vol/results/{run_name}.json", "w") as fh:
        json.dump(result, fh, indent=2)

    if do_train:
        os.makedirs(f"/vol/adapters/{run_name}", exist_ok=True)
        model.save_pretrained(f"/vol/adapters/{run_name}")       # VERIFY LoRA save
        tokenizer.save_pretrained(f"/vol/adapters/{run_name}")

    vol.commit()  # persist result + adapter before the heavy GGUF step
    if cfg.get("export_gguf") and do_train:
        say("exporting GGUF (winner)")
        try:
            # VERIFY: Unsloth GGUF export. E4B is multimodal; export also yields
            # an mmproj projector file we can ignore for a text classifier.
            model.save_pretrained_gguf(
                f"/vol/gguf/{run_name}", tokenizer,
                quantization_method=["q4_k_m", "q8_0"],
            )
            # Unsloth writes the .gguf files (+ an Ollama Modelfile) to "<dir>_gguf";
            # "<dir>" itself only holds the merged 16-bit safetensors.
            result["gguf"] = f"/vol/gguf/{run_name}_gguf"
        except Exception as e:
            say(f"WARN gguf export failed ({e})")
            result["gguf_error"] = str(e)
        with open(f"/vol/results/{run_name}.json", "w") as fh:
            json.dump(result, fh, indent=2)

    vol.commit()  # VERIFY: persist writes so the orchestrator can read them.
    return result


@app.local_entrypoint()
def smoke():
    """One tiny job to prove the whole path works. ~10 min, a few cents."""
    cfg = {
        "run_name": "smoke", "base_model": "unsloth/gemma-4-E2B-it",
        "lr": 2e-4, "seed": 0, "epochs": 1, "load_in_4bit": True,
        "train": True, "export_gguf": True,
        "max_train_rows": 24, "max_eval_rows": 6,
    }
    print(json.dumps(run_job.remote(cfg), indent=2))
