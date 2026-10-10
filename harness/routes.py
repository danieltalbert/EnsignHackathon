"""Flask routes for the harness. Answers only on this computer; POSTs must be JSON, which a
cross-site form can't send, so other web pages can't click Approve for the user."""
from urllib.parse import urlsplit
from flask import Blueprint, jsonify, request
from . import executor
from .service import H

blueprint = Blueprint("harness", __name__, url_prefix="/api/harness")


@blueprint.before_request
def local_only():
    try:
        host = urlsplit("//" + (request.host or "")).hostname
    except ValueError:
        host = None
    if host not in {"127.0.0.1", "localhost", "::1"}:
        return jsonify({"error": "The harness only answers on this computer."}), 403
    if request.method == "POST" and not request.is_json:
        return jsonify({"error": "Send a JSON body."}), 415


@blueprint.get("/state")
def state():
    return jsonify(H.state())


@blueprint.post("/scan")
def scan():
    started = H.scan_now()
    return jsonify({"started": started, "message": "Scanning now." if started else "A scan is already running."})


@blueprint.post("/always_active")
def always_active():
    on = bool((request.get_json(silent=True) or {}).get("on"))
    H.set_always_active(on)
    return jsonify({"always_active": on})


@blueprint.post("/demo")
def demo():
    ok, message = H.run_demo()
    return jsonify({"started": ok, "message": message}), (200 if ok else 403)


@blueprint.post("/cards/<cid>/approve")
def approve(cid):
    body = request.get_json(silent=True) or {}
    res = H.approve(cid, str(body.get("action", "")), bool(body.get("confirm")))
    return jsonify(res) if res else (jsonify({"error": "Card not found."}), 404)


@blueprint.post("/cards/<cid>/ignore")
def ignore(cid):
    return jsonify({"ok": True}) if H.ignore(cid) else (jsonify({"error": "Card not found."}), 404)


@blueprint.post("/undo_isolation")
def undo_isolation():
    return jsonify(H.undo_isolation())


@blueprint.get("/audit")
def audit():
    return jsonify(executor.recent_audit(max(1, min(request.args.get("n", 50, type=int), 500))))
