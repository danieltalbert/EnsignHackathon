"""
Local self-test. No GPU, no Modal, no network. Proves the dataset, schema, eval
metrics, and report generator are all internally consistent before you spend a
cent on Modal. Run it after regenerating data or editing the contract.

    python selftest.py
"""

from __future__ import annotations

import json
import os
import sys

import contract as C
from evaluate import score


def _load(path):
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def check_dataset():
    for split in ("train", "eval_dev", "eval_test"):
        path = f"data/{split}.jsonl"
        assert os.path.exists(path), f"missing {path} (run generate_dataset.py)"
    train, dev, test = _load("data/train.jsonl"), _load("data/eval_dev.jsonl"), _load("data/eval_test.jsonl")

    # every target is schema-valid and every input round-trips through build_messages
    for split, rows in (("train", train), ("dev", dev), ("test", test)):
        for r in rows:
            errs = C.validate_output(r["target"])
            assert not errs, f"{split} target invalid: {errs}"
            assert r["target"]["finding_id"] == r["input"]["finding_id"], "id mismatch"
            msgs = C.build_messages(r["input"])
            assert msgs[0]["role"] == "system" and msgs[1]["role"] == "user"

    # splits disjoint
    keys = [C.canonical_key(r["input"]) for r in train + dev + test]
    assert len(keys) == len(set(keys)), "cross-split overlap"

    # windows paths use backslashes (no learned forward-slash artifact)
    for r in train + dev + test:
        if r["input"]["os"] == "windows":
            for k in ("exe_path", "path"):
                v = r["input"]["finding"].get(k)
                if isinstance(v, str) and v.startswith("C:"):
                    assert "/" not in v, f"windows path has forward slash: {v}"
    print(f"OK dataset: train={len(train)} dev={len(dev)} test={len(test)}, "
          f"splits disjoint, all targets valid")


def check_eval_metrics():
    gold = _load("data/eval_test.jsonl")

    perfect = [{"finding_id": g["target"]["finding_id"], "raw": json.dumps(g["target"])} for g in gold]
    none_obj = lambda fid: {"finding_id": fid, "evidence": ["x", "y"], "threat_type": "none",
                            "severity": "none", "confidence": "high", "actions": [],
                            "explanation": "ok", "escalate": False}
    lazy = [{"finding_id": g["target"]["finding_id"], "raw": json.dumps(none_obj(g["target"]["finding_id"]))} for g in gold]
    junk = [{"finding_id": g["target"]["finding_id"], "raw": "no json here"} for g in gold]

    sp, sl, sj = score(gold, perfect), score(gold, lazy), score(gold, junk)
    assert sp["threat_type_acc"] == 1.0 and sp["benign_fp_rate"] == 0.0, sp
    assert sp["json_valid_rate"] == 1.0, sp
    assert sl["threat_recall"] == 0.0, sl           # always-none misses every threat
    assert sl["benign_fp_rate"] == 0.0, sl
    assert sj["json_valid_rate"] == 0.0 and sj["threat_type_acc"] == 0.0, sj
    print(f"OK eval metrics: perfect composite={sp['composite']}, "
          f"always-none tt_acc={sl['threat_type_acc']}, garbage json={sj['json_valid_rate']}")


def check_report():
    import make_report as mr
    s = lambda a, b: {"dev_tt_acc": a, "dev_fp": b, "dev_json_valid": 1.0, "test_tt_acc": a - 0.02,
                      "test_fp": b, "test_hard_fp": b + 0.02, "test_json_valid": 1.0,
                      "composite": round(a - 0.5 * b, 4), "seconds": 500, "gguf": "/vol/gguf/x"}
    st = {"phase": "report", "started": "x", "ended": "y", "est_cost_usd": 1.0, "winner": None, "runs": {}}
    st["runs"]["sweep_e4b_lr0.0001"] = {"cfg": {"run_name": "sweep_e4b_lr0.0001",
                                        "base_model": "unsloth/gemma-4-E4B-it", "lr": 1e-4},
                                        "status": "done", "summary": s(0.88, 0.03)}
    st["runs"]["base_e4b"] = {"cfg": {"run_name": "base_e4b", "base_model": "unsloth/gemma-4-E4B-it", "lr": 0},
                              "status": "done", "summary": s(0.44, 0.30)}
    st["winner"] = {"run_name": "sweep_e4b_lr0.0001",
                    "cfg": st["runs"]["sweep_e4b_lr0.0001"]["cfg"]}
    md = mr.build(st, "/tmp/_selftest_report.md")
    assert "Winner config" in md and "Do this next" in md
    assert "SYSTEM" in md  # merge steps include the baked prompt
    print("OK report: renders with winner, baseline, and merge steps")


if __name__ == "__main__":
    try:
        check_dataset()
        check_eval_metrics()
        check_report()
    except AssertionError as e:
        print("SELFTEST FAILED:", e)
        sys.exit(1)
    print("\nAll self-tests passed. Safe to deploy to Modal.")
