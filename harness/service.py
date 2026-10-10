"""Background service: scanners -> adapter -> prefilter -> queue (dedupe) -> judge -> router
-> cards / escalation. One finding at a time. If the model is offline the harness keeps
scanning and queueing on the prefilter rules alone, and resumes judging when it returns."""
import json, time, uuid, heapq, itertools, threading, queue
from collections import deque, Counter
from . import config, adapter, prefilter, judge, router, escalate, executor, firewall

SEV = prefilter.SEV
PRIO = {"critical": 1, "high": 2, "medium": 3, "info": 4}
OPEN = ("provisional", "open", "acted")


class Harness:
    def __init__(self):
        self.lock = threading.RLock()
        self.wake = threading.Condition(self.lock)
        self.heap, self.seq = [], itertools.count()
        self.cards, self.by_key, self.seen, self.watch = {}, {}, {}, set()
        self.events, self.stats = deque(maxlen=200), Counter()
        self.model = {"online": False, "state": "checking", "message": "Checking the model server…",
                      "name": config.OLLAMA_MODEL}
        self.always_active = config.ALWAYS_ACTIVE
        self.scanners, self.last_run = {}, {}
        self.scan_lock, self.manual = threading.Lock(), threading.Event()
        self.escalations, self.recheck = queue.Queue(), threading.Event()
        self.busy, self.demo_run, self.started = None, 0, False

    # --- lifecycle --------------------------------------------------------------

    def start(self, scanners):
        with self.lock:
            if self.started:
                return
            self.started, self.scanners = True, dict(scanners)
        for fn in (self._health, self._worker, self._escalator, self._scheduler):
            threading.Thread(target=fn, daemon=True, name=f"harness{fn.__name__}").start()
        self.log(f"Harness started on {config.OS}" + (" in DEMO_MODE: every action is a dry run." if config.DEMO_MODE else "."))

    def log(self, msg):
        with self.lock:
            self.events.appendleft({"ts": time.strftime("%H:%M:%S"), "msg": msg})

    def set_always_active(self, on):
        with self.lock:
            self.always_active = on
        self.log(f"Always-Active turned {'on' if on else 'off'}.")

    # --- intake -----------------------------------------------------------------

    def submit_findings(self, findings, mode):
        try:
            adapter.prepare(findings)
        except Exception as e:
            self.log(f"Adapter baseline error: {e}")
        for f in findings:
            try:
                item = adapter.adapt(f, mode)
                if item:
                    self.submit(item, PRIO.get(f.get("severity"), 4))
            except Exception as e:
                self.log(f"Adapter error on '{f.get('title')}': {e}")

    def submit(self, item, prio):
        key, now = item["key"], time.time()
        with self.lock:
            exp = self.seen.get(key)
            if exp is not None and (exp == 0 or exp > now):
                self.stats["deduped"] += 1
                return False
            self.seen[key] = 0  # pending
            watched = key in self.watch
        skip, flags, level = prefilter.screen(item, watched)
        item.update(flags=flags, level=level)
        if skip:
            self._done(key)
            self.stats["skipped"] += 1
            self.log(f"Prefilter: normal, not sent to the model: {self._name(item)}")
            return False
        if item["input"] is None:  # no contract shape for this finding: rules only
            if SEV.index(level) >= SEV.index("medium"):
                self._card(item, status="open", route="notify", severity=level,
                           notes=["Rules only: this kind of finding isn't sent to the model."])
            else:
                self.log(f"Logged (rules only): {self._name(item)}")
            self._done(key)
            return True
        with self.wake:
            heapq.heappush(self.heap, (prio, next(self.seq), item))
            if not self.model["online"]:
                self._provisional(item)
            self.wake.notify_all()
        return True

    def _done(self, key):
        with self.lock:
            now = time.time()
            self.seen[key] = now + (300 if key in self.watch else config.DEDUPE_TTL)
            if len(self.seen) > 20000:  # long sessions: forget expired dedupe keys
                self.seen = {k: v for k, v in self.seen.items() if v == 0 or v > now}

    @staticmethod
    def _name(item):
        inp, rule = item.get("input") or {}, item.get("rule") or {}
        f = inp.get("finding") or {}
        what = (f.get("name") or f.get("path") or f.get("ip") or f.get("backup_path") or
                (f"{f.get('count')} files {f.get('event', 'changed')}" if f.get("kind") == "burst" else None) or
                rule.get("title") or "finding")
        return f"{inp.get('source') or rule.get('category', '').lower()} · {what}"

    # --- cards ------------------------------------------------------------------

    def _card(self, item, **kw):
        with self.lock:
            c = self.cards.get(self.by_key.get(item["key"]))
            if c is None or c["status"] not in OPEN:
                inp = item.get("input") or {}
                c = {"id": uuid.uuid4().hex, "key": item["key"], "created": time.time(), "origin": item["origin"],
                     "source": inp.get("source") or (item.get("rule") or {}).get("category", "").lower(),
                     "finding_id": inp.get("finding_id") or (item.get("rule") or {}).get("id"),
                     "finding": inp.get("finding"), "rule": item.get("rule"), "label": item.get("label"),
                     "flags": item.get("flags") or [], "judgement": None, "escalation": None, "actions": [],
                     "notes": [], "_item": item}
                self.cards[c["id"]], self.by_key[item["key"]] = c, c["id"]
            c.update(kw, updated=time.time())
            return c

    def _provisional(self, item):
        c = self.cards.get(self.by_key.get(item["key"]))
        if SEV.index(item["level"]) >= SEV.index("medium") and not (c and c["status"] in OPEN):
            self._card(item, status="provisional", route="notify", severity=item["level"],
                       notes=["Model offline: queued for judgement. Showing rule flags meanwhile."])

    def _drop_card(self, key):
        with self.lock:
            c = self.cards.get(self.by_key.get(key))
            if c and c["status"] == "provisional":
                del self.cards[c["id"]]
                del self.by_key[key]

    # --- judge ------------------------------------------------------------------

    def _worker(self):
        while True:
            with self.wake:
                while not (self.heap and self.model["online"]):
                    self.wake.wait(5)
                prio, seq, item = heapq.heappop(self.heap)
                self.busy = item
            try:
                status, j, problems = judge.judge(item["input"])
            except judge.Offline as e:
                with self.wake:
                    heapq.heappush(self.heap, (prio, seq, item))
                    self.busy = None
                self._set_model(False, str(e))
                self.recheck.set()
                continue
            except Exception as e:
                status, j, problems = "invalid", None, [f"{type(e).__name__}: {e}"]
            with self.lock:
                self.busy = None
            try:
                self._judged(item, j, problems)
            except Exception as e:
                self.log(f"Router error on {self._name(item)}: {e}")
                self._done(item["key"])

    def _judged(self, item, j, problems):
        self.stats["judged"] += 1
        reason = router.needs_escalation(j, item)
        sev = j["severity"] if j else item["level"]
        rt = router.route(sev) if j else "notify"
        if j is None:
            self.stats["invalid"] += 1
        if rt == "log" and not reason:
            self.stats["cleared"] += 1
            self.log(f"Model cleared as normal ({j['confidence']} confidence): {self._name(item)}")
            self._drop_card(item["key"])
            self._done(item["key"])
            return
        guidance = " ".join(x for x in (j and j.get("explanation"), (item.get("rule") or {}).get("recommendation")) if x)
        actions = []
        if rt == "approve":
            for a in j["actions"]:
                act = router.action(a, item, guidance=guidance)
                if act and not any(x["name"] == act["name"] for x in actions):
                    actions.append(act)
        notes = [] if j else [f"Model reply was invalid twice ({'; '.join(problems or [])[:160]}); escalated instead of dropped."]
        c = self._card(item, status="open", route=rt, severity=sev, judgement=j, actions=actions, notes=notes,
                       escalation={"status": "pending", "reason": reason} if reason else None)
        self.log(f"Judged {sev}: {self._name(item)}" + (f" → escalating ({reason})" if reason else ""))
        if reason:
            self.escalations.put((c["id"], reason))
        self._done(item["key"])

    # --- escalation -------------------------------------------------------------

    def _escalator(self):
        while True:
            cid, reason = self.escalations.get()
            with self.lock:
                c = self.cards.get(cid)
            if not c:
                continue
            try:
                res = escalate.review(c, reason)
            except Exception as e:
                res = {"status": "unavailable", "message": f"Escalation failed: {e}. The local judgement stands."}
            res["reason"] = reason
            steps, item = [], c["_item"]
            for step in res.get("plan", []):
                act = router.action(step["tool"], item, origin="escalation",
                                    guidance=res.get("guidance") or (c["judgement"] or {}).get("explanation", ""))
                if act is None:
                    continue
                if act["changes"]:  # proposed only; the user must approve
                    with self.lock:
                        if not any(x["name"] == act["name"] for x in c["actions"]):
                            c["actions"].append(act)
                    continue
                out = act["reason"]
                if act["available"]:  # read-only: runs freely, still audited
                    r = executor.execute(act["name"], act["target"], card_id=cid, finding_id=c["finding_id"],
                                         demo_target=c["origin"] == "demo")
                    out = r["message"]
                    if act["name"] == "monitor" and r["status"] == "done" and c["origin"] != "demo":
                        self.watch.add(c["key"])
                steps.append({"tool": act["name"], "label": act["label"], "why": step["why"], "result": out})
            res["steps"] = steps
            with self.lock:
                c["escalation"] = res
                if res.get("severity"):
                    c["severity"] = res["severity"]
                if any(a["changes"] and a["available"] for a in c["actions"]):
                    c["route"] = "approve"
                c["updated"] = time.time()
            self.log(f"Escalation {res['status']}: {self._name(item)}")

    # --- model health -------------------------------------------------------------

    def _set_model(self, ok, msg):
        with self.wake:
            was = self.model["online"]
            self.model.update(online=ok, state="online" if ok else "offline", message=msg)
            if ok and not was:
                self.wake.notify_all()
            if not ok:
                for _, _, item in self.heap:
                    self._provisional(item)
        if ok and not was:
            self.log("Model online: judging queued findings.")
        elif was and not ok:
            self.log(f"Model offline ({msg}) Prefilter rules only; findings stay queued.")

    def _health(self):
        while True:
            ok, msg = judge.ping()
            self._set_model(ok, msg)
            self.recheck.clear()
            if self.recheck.wait(60 if ok else config.HEALTH_INTERVAL):
                self.recheck.clear()
                time.sleep(config.HEALTH_INTERVAL)  # back off after a failed judge call

    # --- scanning ---------------------------------------------------------------

    def _scheduler(self):
        while True:
            for name, cfg in config.SCANNERS.items():
                if name not in self.scanners or cfg["mode"] == "off":
                    continue
                if cfg["mode"] == "always_active" and not self.always_active:
                    continue
                if time.time() - self.last_run.get(name, 0) >= cfg["interval"]:
                    self._run(name, cfg["mode"])
            time.sleep(1)

    def _run(self, name, mode):
        findings = []
        with self.scan_lock:
            try:
                self.scanners[name](findings)
            except Exception as e:
                self.log(f"{name} scanner failed: {e}")
            self.last_run[name] = time.time()
        self.submit_findings(findings, mode)

    def scan_now(self):
        if self.manual.is_set():
            return False
        self.manual.set()

        def go():
            try:
                for name in list(self.scanners):
                    self._run(name, "manual")
            finally:
                self.manual.clear()
                self.log("Manual scan finished.")
        threading.Thread(target=go, daemon=True).start()
        return True

    # --- demo replay ------------------------------------------------------------

    def run_demo(self):
        if not config.DEMO_MODE:
            return False, "Set DEMO_MODE=1 in .env to enable the demo replay."
        try:
            rows = [json.loads(x) for x in config.EVAL_TEST.read_text(encoding="utf-8").splitlines() if x.strip()]
        except (OSError, ValueError) as e:
            return False, f"Can't read {config.EVAL_TEST.name}: {e}"
        picks, kinds = [], set()
        for r in rows:  # one per threat type, plus a look-alike that gets past the prefilter for the model to clear
            kind = "hard_negative" if r["meta"].get("is_hard_negative") else r["target"]["threat_type"]
            if kind == "hard_negative" and prefilter.screen({"input": r["input"]})[0]:
                continue
            if kind not in kinds:
                kinds.add(kind)
                picks.append(r)
        with self.lock:
            self.demo_run += 1
            run = self.demo_run
            self.heap = [x for x in self.heap if x[2]["origin"] != "demo"]
            heapq.heapify(self.heap)
            for c in [c for c in self.cards.values() if c["origin"] == "demo"]:
                del self.cards[c["id"]]
                self.by_key.pop(c["key"], None)
        for r in picks:
            self.submit({"key": f"demo|{run}|{r['input']['finding_id']}", "input": r["input"], "ctx": {},
                         "rule": None, "origin": "demo", "label": r["target"]["threat_type"] +
                         (" (hard negative)" if r["meta"].get("is_hard_negative") else "")}, 0)
        self.log(f"Demo replay #{run}: {len(picks)} labeled findings from eval_test.jsonl.")
        return True, f"Replaying {len(picks)} labeled findings through the live pipeline (all actions are dry runs)."

    # --- user decisions -----------------------------------------------------------

    def approve(self, cid, name, confirm=False):
        with self.lock:
            c = self.cards.get(cid)
            if not c or c["status"] not in OPEN:
                return None
            act = next((a for a in c["actions"] if a["name"] == name), None)
            if not act or not act["available"] or act["state"] in ("running", "done", "dry_run"):
                return {"status": "refused", "message": "That action isn't available on this card."}
            act["state"] = "running"
        res = executor.execute(name, act["target"], card_id=cid, finding_id=c["finding_id"], approved=True,
                               confirm=confirm, demo_target=c["origin"] == "demo")
        st = res["status"]
        with self.lock:
            act["state"], act["message"] = ("proposed" if st == "needs_confirm" else st), res["message"]
            if st == "aborted":  # target changed under us: refresh the card instead of acting
                act["available"], act["reason"] = False, res["message"]
                c["notes"].append("Card refreshed: " + res["message"])
            if st in ("done", "dry_run"):
                c["status"] = "acted"
                undo = executor.REGISTRY[name].get("undo")
                if undo and not any(a["name"] == undo for a in c["actions"]):
                    c["actions"].append(router.make(undo, res.get("undo", act["target"]), origin="undo"))
                if name == "monitor":
                    self.watch.add(c["key"])
            c["updated"] = time.time()
        if st != "needs_confirm":
            self.log(f"{act['label']}: {res['message']}")
        return res

    def ignore(self, cid):
        with self.lock:
            c = self.cards.get(cid)
            if not c:
                return False
            c["status"] = "ignored"
        executor.audit(finding_id=c["finding_id"], card_id=cid, action="ignore", target=None, approved_by_user=True,
                       elevated=False, dry_run=False, result="dismissed", message="Card ignored by the user.", error=None)
        return True

    def undo_isolation(self):
        return executor.execute("undo_isolation", {}, approved=True)

    # --- view -----------------------------------------------------------------------

    def state(self):
        with self.lock:
            cards = [{k: v for k, v in c.items() if not k.startswith("_") and k != "key"}
                     for c in self.cards.values() if c["status"] in OPEN]
            busy = self._name(self.busy) if self.busy else None
            out = {"model": dict(self.model), "always_active": self.always_active, "demo_mode": config.DEMO_MODE,
                   "os": config.OS, "queue": len(self.heap), "judging": busy, "stats": dict(self.stats),
                   "events": list(self.events)[:8], "scanning": self.manual.is_set(),
                   "escalation_model": config.GEMINI_MODEL if config.GEMINI_API_KEY else None,
                   "modes": [{"scanner": n, "mode": m["mode"], "interval": m["interval"],
                              "available": n in self.scanners, "last_run": self.last_run.get(n)}
                             for n, m in config.SCANNERS.items()]}
        cards.sort(key=lambda c: (c["status"] == "acted", -SEV.index(c.get("severity") or "none"), -c["created"]))
        out["cards"] = cards[:60]
        out["isolated"] = firewall.load()["isolated"]
        return out


H = Harness()
