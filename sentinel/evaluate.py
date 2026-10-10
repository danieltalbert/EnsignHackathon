"""
Honest eval for Sentinel models.

Given gold rows (input/target/meta) and the model's raw text outputs, compute
metrics that actually matter for a security tool:

  json_valid_rate      fraction of outputs that parse + satisfy the schema.
                       In production Ollama's `format` enforces this, so raw
                       parse rate here is a FLOOR, not the production number.
  threat_type_acc      exact threat_type match (an unparseable output = wrong).
  severity_acc         exact severity match.
  threat_recall        of real threats, fraction the model flagged as non-none
                       (i.e. did not miss).
  benign_fp_rate       of truly-benign findings, fraction wrongly flagged.
                       A tool that cries wolf gets muted, so this is weighted.
  hard_neg_fp_rate     benign_fp_rate restricted to the hard negatives (a game
                       pinning CPU, Steam rewriting files, Plex's ports...).
  composite            threat_type_acc - 0.5 * benign_fp_rate. Ranking score.

Predictions are matched to gold by finding_id when present, else by order.

CLI:  python evaluate.py --gold data/eval_test.jsonl --pred preds.jsonl
      (preds.jsonl: one JSON per line, {"finding_id": "...", "raw": "<model text>"})
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from typing import Any

from contract import extract_json, validate_output


def _norm_pred(raw: str) -> tuple[dict | None, bool]:
    """Return (parsed_obj_or_None, is_schema_valid)."""
    obj = extract_json(raw if isinstance(raw, str) else json.dumps(raw))
    if obj is None:
        return None, False
    return obj, (len(validate_output(obj)) == 0)


def score(gold_rows: list[dict], preds: list[dict]) -> dict[str, Any]:
    """gold_rows: [{input,target,meta}]; preds: [{finding_id?, raw}] aligned or
    matchable by finding_id."""
    by_id = {p.get("finding_id"): p for p in preds if p.get("finding_id")}
    use_id = len(by_id) == len(gold_rows)

    n = len(gold_rows)
    json_valid = 0
    tt_correct = 0
    sev_correct = 0

    threat_total = 0
    threat_caught = 0
    benign_total = 0
    benign_fp = 0
    hard_total = 0
    hard_fp = 0

    per_source = defaultdict(lambda: {"n": 0, "tt_correct": 0})
    confusion = defaultdict(int)  # (gold_tt, pred_tt) -> count

    for i, g in enumerate(gold_rows):
        tgt = g["target"]
        meta = g.get("meta", {})
        gold_tt = tgt["threat_type"]
        gold_sev = tgt["severity"]
        src = meta.get("source", g["input"].get("source", "?"))

        p = by_id.get(tgt["finding_id"]) if use_id else (preds[i] if i < len(preds) else None)
        raw = (p or {}).get("raw", "")
        obj, valid = _norm_pred(raw)
        if valid:
            json_valid += 1
        pred_tt = (obj or {}).get("threat_type") if valid else None
        pred_sev = (obj or {}).get("severity") if valid else None

        if pred_tt == gold_tt:
            tt_correct += 1
            per_source[src]["tt_correct"] += 1
        if pred_sev == gold_sev:
            sev_correct += 1
        per_source[src]["n"] += 1
        confusion[(gold_tt, pred_tt or "INVALID")] += 1

        is_threat = gold_tt != "none"
        pred_is_threat = (pred_tt is not None) and (pred_tt != "none")
        if is_threat:
            threat_total += 1
            if pred_is_threat:
                threat_caught += 1
        else:
            benign_total += 1
            if pred_is_threat:
                benign_fp += 1
            if meta.get("is_hard_negative"):
                hard_total += 1
                if pred_is_threat:
                    hard_fp += 1

    def rate(a, b):
        return round(a / b, 4) if b else None

    tt_acc = rate(tt_correct, n)
    benign_fp_rate = rate(benign_fp, benign_total) or 0.0
    composite = round((tt_acc or 0.0) - 0.5 * benign_fp_rate, 4)

    return {
        "n": n,
        "json_valid_rate": rate(json_valid, n),
        "threat_type_acc": tt_acc,
        "severity_acc": rate(sev_correct, n),
        "threat_recall": rate(threat_caught, threat_total),
        "benign_fp_rate": benign_fp_rate,
        "hard_neg_fp_rate": rate(hard_fp, hard_total),
        "composite": composite,
        "per_source_tt_acc": {
            s: rate(d["tt_correct"], d["n"]) for s, d in sorted(per_source.items())
        },
        "counts": {
            "threat_total": threat_total, "benign_total": benign_total,
            "hard_total": hard_total,
        },
    }


def load_jsonl(path: str) -> list[dict]:
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gold", required=True)
    ap.add_argument("--pred", required=True)
    args = ap.parse_args()
    gold = load_jsonl(args.gold)
    preds = load_jsonl(args.pred)
    print(json.dumps(score(gold, preds), indent=2))


if __name__ == "__main__":
    main()
