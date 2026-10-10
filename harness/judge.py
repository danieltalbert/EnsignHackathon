"""JUDGE: one finding -> the fine-tuned model over the Ollama funnel -> contract judgement."""
import json, http.client, urllib.request, urllib.error
from . import config

contract = config.contract


class Offline(Exception):
    """Model endpoint unreachable, timing out, or not serving the model."""


def post_json(url, body, timeout, headers=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout, context=config.SSL_CONTEXT) as r:
        return json.loads(r.read().decode())


def _ask(finding):
    if not config.OLLAMA_URL:
        raise Offline("OLLAMA_URL is not set.")
    body = {"model": config.OLLAMA_MODEL, "messages": contract.build_messages(finding),
            "stream": False, "think": False, "format": contract.OUTPUT_JSON_SCHEMA,
            "options": {"temperature": 0}}
    try:
        data = post_json(config.OLLAMA_URL + "/api/chat", body, config.JUDGE_TIMEOUT)
    except urllib.error.HTTPError as e:
        raise Offline(f"Model server returned HTTP {e.code}.")
    except (OSError, ValueError, http.client.HTTPException) as e:
        slow = isinstance(getattr(e, "reason", e), TimeoutError)
        raise Offline(f"No reply within {config.JUDGE_TIMEOUT}s." if slow else f"Unreachable: {str(e)[:160]}")
    return (data.get("message") or {}).get("content", "")


def judge(finding):
    """('ok', judgement, None) or ('invalid', None, problems). Retries once. Raises Offline."""
    problems = []
    for _ in range(2):
        obj = contract.extract_json(_ask(finding))
        problems = contract.validate_output(obj) if obj is not None else ["reply had no JSON object"]
        if not problems and obj["finding_id"] != finding["finding_id"]:
            problems = ["finding_id does not match the input"]
        if not problems:
            obj["actions"] = [a for a in obj["actions"] if a != "none"]
            return "ok", obj, None
    return "invalid", None, problems


def ping():
    """(online, message). Online means the server answers and serves OLLAMA_MODEL."""
    if not config.OLLAMA_URL:
        return False, "OLLAMA_URL is not set in .env."
    try:
        req = urllib.request.Request(config.OLLAMA_URL + "/api/tags")
        with urllib.request.urlopen(req, timeout=8, context=config.SSL_CONTEXT) as r:
            names = {m.get("name") for m in json.loads(r.read().decode()).get("models", [])}
    except urllib.error.HTTPError as e:
        return False, f"Model server returned HTTP {e.code}."
    except (OSError, ValueError, http.client.HTTPException) as e:
        return False, f"Model server unreachable ({str(getattr(e, 'reason', e))[:120]})."
    m = config.OLLAMA_MODEL
    if m not in names and f"{m}:latest" not in names:
        return False, f"Server is up but has no '{m}' model."
    return True, ""
