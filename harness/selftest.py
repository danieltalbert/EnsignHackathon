"""Offline self-test for the harness: no real model, no admin prompts, nothing outside a temp dir.

    python -m harness.selftest

Covers: prefilter vs every labeled row, adapter on this machine's real scanners, router target
resolution, executor (dry run, refusals, confirm, unsupported OS, declined prompt, PID reuse,
real kill/quarantine on throwaway targets), firewall rule builders, judge retry/offline against
a fake Ollama, and the full service loop including model-offline -> recovery.
"""
import json, os, sys, time, shutil, tempfile, threading, subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from harness import config, adapter, prefilter, router, executor, firewall, elevate, judge, service

TMP = Path(tempfile.mkdtemp(prefix="sentinel-selftest-"))
config.AUDIT_LOG, config.QUARANTINE, config.STATE_DIR = TMP / "audit.jsonl", TMP / "quarantine", TMP / "state"
firewall.STATE = config.STATE_DIR / "firewall.json"
DATA = config.ROOT / "sentinel" / "data"
ROWS = {s: [json.loads(x) for x in (DATA / f"{s}.jsonl").read_text().splitlines() if x.strip()]
        for s in ("train", "eval_dev", "eval_test")}
BY_ID = {r["input"]["finding_id"]: r for rows in ROWS.values() for r in rows}
passed = 0


def ok(cond, msg):
    global passed
    if not cond:
        print("FAIL:", msg)
        sys.exit(1)
    passed += 1


def test_prefilter():
    for split, rows in ROWS.items():
        missed = [r["meta"]["scenario"] for r in rows
                  if prefilter.screen({"input": r["input"]})[0] and r["target"]["threat_type"] != "none"]
        ok(not missed, f"prefilter skipped threats in {split}: {missed}")
        benign = [r for r in rows if r["target"]["threat_type"] == "none"]
        skipped = sum(prefilter.screen({"input": r["input"]})[0] for r in benign)
        print(f"  prefilter {split}: 0 threats skipped, {skipped}/{len(benign)} normal findings skipped")
    weak = [r["meta"]["scenario"] for r in ROWS["eval_test"] if r["target"]["threat_type"] != "none"
            and prefilter.screen({"input": r["input"]})[2] not in ("medium", "high", "critical")]
    ok(not weak, f"threats with no offline (rules-only) flag: {weak}")


def test_adapter():
    import app  # Luke's scanners; importing does not start the harness
    findings = []
    app.process_snapshot(findings)
    app.network_snapshot(findings)
    app.storage_snapshot(findings)
    ok(all("target" in f for f in findings), "every scanner finding carries a target")
    adapter.prepare(findings)
    items = [i for i in (adapter.adapt(f, "manual") for f in findings[:400]) if i]
    contract_items = [i for i in items if i["input"]]
    need = {"processes": ("name", "pid"), "network": ("ip",), "storage": ("kind",)}
    for i in contract_items:
        inp = i["input"]
        ok(inp["source"] in config.contract.SOURCES and inp["os"] in config.contract.OSES, f"bad envelope {inp}")
        ok(all(k in inp["finding"] for k in need[inp["source"]]), f"missing required fields {inp}")
        if inp["finding"].get("kind") == "file":
            ok("path" in inp["finding"] and "event" in inp["finding"], f"file finding incomplete {inp}")
    skipped = sum(prefilter.screen(i)[0] for i in contract_items)
    print(f"  adapter: {len(findings)} real findings -> {len(contract_items)} contract inputs, "
          f"{len(items) - len(contract_items)} rules-only, prefilter skips {skipped}")


def test_router():
    for r in ROWS["eval_test"]:
        j, f = r["target"], r["input"]["finding"]
        item = {"key": "k", "input": r["input"], "ctx": {}}
        for a in j["actions"]:
            act = router.action(a, item)
            if act and act["available"] and act["name"] == "kill_process":
                ok(act["target"]["pid"] == f["pid"], "kill target must be the finding's pid")
            if act and act["available"] and act["name"] == "quarantine_file":
                ok(act["target"]["path"] in (f.get("path"), f.get("exe_path")), "quarantine target must come from finding")
            if act and act["name"] == "block_address":
                ok(all(any(x in e for e in f.get("remote_endpoints", []) + [f.get("ip", "")])
                       for x in act["target"]["addresses"]), "block target must come from finding")
    base = {"finding_id": "x", "evidence": ["a", "b"], "threat_type": "cryptominer", "severity": "high",
            "confidence": "high", "actions": [], "explanation": "e", "escalate": False}
    ok(router.needs_escalation(base, {}) is None, "confident judgement should not escalate")
    ok(router.needs_escalation({**base, "confidence": "low"}, {}), "low confidence escalates")
    ok(router.needs_escalation({**base, "escalate": True}, {}), "escalate flag escalates")
    ok(router.needs_escalation({**base, "threat_type": "other_suspicious"}, {}), "other_suspicious escalates")
    ok(router.needs_escalation(None, {}), "invalid judgement escalates")
    ok([router.route(s) for s in ("none", "low", "medium", "high", "critical")] ==
       ["log", "notify", "approve", "approve", "approve"], "routing table")
    net = {"key": "k", "input": {"source": "network", "finding": {"ip": "192.168.1.9", "is_this_device": True,
                                                                  "open_ports": [{"port": 3389}]}}}
    ok(router.action("disconnect_network", net)["name"] == "disconnect_network", "no remote address -> isolate")
    ok(router.action("close_port", net)["target"] == {"ports": [3389]}, "close_port takes the finding's port")


def test_executor():
    targets = {"kill_process": {"pid": 424242, "name": "x"}, "quarantine_file": {"path": "/tmp/x"},
               "disconnect_network": {}, "block_address": {"addresses": ["203.0.113.5"]},
               "close_port": {"ports": [4444]}, "run_backup": {}, "restore_backup": {"backup_path": "/b"}}
    with mock.patch.object(config, "DEMO_MODE", True):
        for name, t in targets.items():
            r = executor.execute(name, t, approved=True, confirm=True)
            want = "unsupported" if "backup" in name else "dry_run"
            ok(r["status"] == want, f"DEMO_MODE {name} -> {r}")
            if want == "dry_run":
                ok("Elevation prompt" in r["message"], "dry run names the elevation prompt")
        ok(executor.execute("restore_backup", {"backup_path": "/b"}, approved=True)["status"] == "needs_confirm",
           "restore asks for a second confirmation")
    ok(executor.execute("kill_process", {"pid": 1}, approved=False)["status"] == "refused", "needs approval")
    with mock.patch.object(config, "OS", "plan9"):
        ok(executor.execute("close_port", {"ports": [1]}, approved=True)["status"] == "unsupported", "unknown OS")
    with mock.patch.object(config, "DEMO_MODE", False):
        _real_actions()


def _real_actions():
    # Real, non-elevated actions on throwaway targets only.
    p = subprocess.Popen(["sleep", "300"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.3)
    import psutil
    proc = psutil.Process(p.pid)
    good = {"pid": p.pid, "name": proc.name(), "create_time": proc.create_time()}
    ok(executor.execute("kill_process", {**good, "name": "not-sleep"}, approved=True)["status"] == "aborted",
       "PID that no longer matches the finding aborts")
    ok(executor.execute("kill_process", {**good, "create_time": 1.0}, approved=True)["status"] == "aborted",
       "reused PID (different start time) aborts")
    r = executor.execute("kill_process", good, approved=True)
    ok(r["status"] == "done" and p.wait(timeout=5) is not None, f"kill own throwaway process: {r}")

    f = TMP / "dropper sample.sh"
    f.write_text("echo hi\n")
    os.chmod(f, 0o755)
    r = executor.execute("quarantine_file", {"path": str(f)}, approved=True)
    ok(r["status"] == "done" and not f.exists(), f"quarantine: {r}")
    meta = json.loads((config.QUARANTINE / f"{r['undo']['qid']}.json").read_text())
    ok(meta["original_path"] == str(f) and len(meta["sha256"]) == 64, "quarantine record has path + hash")
    ok(not os.access(config.QUARANTINE / f"{r['undo']['qid']}.bin", os.X_OK), "quarantined copy is not executable")
    r = executor.execute("restore_file", r["undo"], approved=True)
    ok(r["status"] == "done" and f.exists() and os.access(f, os.X_OK), f"restore: {r}")
    ok(executor.execute("quarantine_file", {"path": "/bin/ls"}, approved=True)["status"] == "refused",
       "never quarantines protected system files")

    # Declined OS prompt: card stays open, no retry.
    fake = subprocess.CompletedProcess([], 1, "", "execution error: User canceled. (-128)")
    with mock.patch.object(config, "OS", "macos"), mock.patch.object(elevate.subprocess, "run", return_value=fake), \
         mock.patch.object(firewall, "endpoint_ips", return_value=["198.51.100.7"]):
        ok(executor.execute("disconnect_network", {}, approved=True)["status"] == "declined", "cancel -> declined")
    ok(not firewall.load()["isolated"], "declined isolation leaves state untouched")


def test_audit():
    lines = [json.loads(x) for x in config.AUDIT_LOG.read_text().splitlines()]
    ok(all({"ts", "finding_id", "action", "target", "approved_by_user", "elevated", "dry_run", "result", "error"}
           <= set(x) for x in lines), "audit records have every field")


def test_firewall_rules():
    s = {**firewall.EMPTY, "isolated": True, "allow": ["198.51.100.7", "2001:db8::7"],
         "blocked": ["203.0.113.5"], "ports": [4444]}
    pf = firewall.pf_rules(s)
    ok(pf.index("table <sentinel_allow>") < pf.index("pass out quick to <sentinel_allow>"), "pf tables first")
    ok(pf.rstrip().endswith("block drop quick all") and "port 53" in pf and "on ! lo0" in pf, "pf isolation shape")
    nft = firewall.nft_rules(s)
    ok("elements = { 198.51.100.7 }" in nft and "ip6 daddr @allow6 accept" in nft and nft.count("    drop") == 2,
       "nft isolation shape")
    ok("ct state established" not in nft, "isolation doesn't keep pre-existing connections alive")
    win = firewall.netsh_lines(firewall.EMPTY, s)
    ok(any("blockinbound,blockoutbound" in x for x in win) and any("remoteip=198.51.100.7" in x for x in win),
       "windows isolation shape")
    undo = firewall.netsh_lines({**s, "win_prev": {"public": {"state": "on", "policy": "blockinbound,allowoutbound"}}},
                                firewall.EMPTY)
    ok(any("publicprofile firewallpolicy blockinbound,allowoutbound" in x for x in undo), "windows undo restores policy")
    if config.OS == "macos":  # AppleScript quoting round trip, without admin
        tricky = "a \"quoted\" path\\with $HOME and 'single'"
        script = f"printf %s {elevate.q(tricky)}"
        out = subprocess.run(["osascript", "-e", f"do shell script {elevate._applescript(script)}"],
                             capture_output=True, text=True).stdout.rstrip("\n")
        ok(out == tricky, f"AppleScript/shell quoting round trip: {out!r}")


class FakeOllama(BaseHTTPRequestHandler):
    mode = "good"  # good | bad | bad_once | down
    calls = 0

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if FakeOllama.mode == "down":
            return self._send(502, {})
        self._send(200, {"models": [{"name": "sentinel:latest"}]})

    def do_POST(self):
        FakeOllama.calls += 1
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert req["think"] is False and req["options"]["temperature"] == 0 and req["format"]["type"] == "object"
        if FakeOllama.mode == "down":
            return self._send(502, {})
        fid = json.loads(req["messages"][1]["content"].split("\n\n", 1)[1])["finding_id"]
        bad = FakeOllama.mode == "bad" or (FakeOllama.mode == "bad_once" and FakeOllama.calls % 2 == 1)
        content = "sorry, no JSON" if bad else json.dumps(BY_ID[fid]["target"])
        self._send(200, {"message": {"role": "assistant", "content": content}})


def test_judge_and_service():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeOllama)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    row = next(r for r in ROWS["eval_test"] if r["target"]["threat_type"] == "cryptominer")
    with mock.patch.object(config, "OLLAMA_URL", url), mock.patch.object(config, "OLLAMA_MODEL", "sentinel"), \
         mock.patch.object(config, "GEMINI_API_KEY", ""), mock.patch.object(config, "HEALTH_INTERVAL", 1), \
         mock.patch.object(config, "DEMO_MODE", True):
        FakeOllama.mode = "good"
        ok(judge.judge(row["input"])[0] == "ok", "valid reply")
        FakeOllama.mode, FakeOllama.calls = "bad_once", 0
        ok(judge.judge(row["input"])[0] == "ok" and FakeOllama.calls == 2, "invalid once -> retried")
        FakeOllama.mode, FakeOllama.calls = "bad", 0
        st, j, problems = judge.judge(row["input"])
        ok(st == "invalid" and FakeOllama.calls == 2 and problems, "invalid twice -> invalid after one retry")
        FakeOllama.mode = "down"
        try:
            judge.judge(row["input"])
            ok(False, "down server should raise Offline")
        except judge.Offline:
            pass
        ok(judge.ping()[0] is False, "ping reports offline")

        # Full loop: start offline, queue the demo, come back online, drain.
        h = service.Harness()
        h.start({})
        time.sleep(1.5)
        ok(not h.model["online"], "service sees model offline")
        ok(h.run_demo()[0], "demo replay starts")
        time.sleep(0.5)
        st = h.state()
        ok(st["queue"] > 0 and any(c["status"] == "provisional" for c in st["cards"]),
           "offline: findings stay queued with rules-only provisional cards")
        FakeOllama.mode = "good"
        for _ in range(60):
            time.sleep(0.5)
            st = h.state()
            if st["queue"] == 0 and not st["judging"] and h.escalations.empty():
                break
        time.sleep(1)
        st = h.state()
        ok(st["model"]["online"] and st["queue"] == 0, "model recovered and the queue drained")
        ok(not any(c["status"] == "provisional" for c in st["cards"]), "provisional cards replaced by judgements")
        threats = {r["target"]["threat_type"] for r in ROWS["eval_test"]} - {"none"}
        seen = {c["judgement"]["threat_type"] for c in st["cards"] if c.get("judgement")}
        ok(threats <= seen, f"one card per threat type, missing {threats - seen}")
        ok(st["stats"].get("skipped", 0) >= 1 and st["stats"].get("cleared", 0) >= 1, "normal finding skipped, hard negative cleared by the model")
        escalated = [c for c in st["cards"] if c.get("escalation")]
        ok(escalated and all(c["escalation"]["status"] in ("unavailable", "done") for c in escalated),
           "escalations resolve (Gemini disabled here -> 'unavailable', card kept)")
        card = next(c for c in st["cards"] if any(a["name"] == "kill_process" and a["available"] for a in c["actions"]))
        r = h.approve(card["id"], "kill_process")
        ok(r["status"] == "dry_run", f"approve in DEMO_MODE is a dry run: {r}")
        ok(h.approve(card["id"], "kill_process")["status"] == "refused", "an action can't run twice")
        ok(h.ignore(card["id"]) and all(c["id"] != card["id"] for c in h.state()["cards"]), "ignore hides the card")
        print(f"  service: {len(st['cards'])} cards, stats {st['stats']}")
    srv.shutdown()


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            print(name)
            fn()
    shutil.rmtree(TMP, ignore_errors=True)
    print(f"harness selftest OK: {passed} checks")
