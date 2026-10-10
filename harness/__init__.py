"""Sentinel triage harness.

scanner output -> adapter (contract shape) -> prefilter -> queue with dedupe -> judge (sentinel
model over the Ollama funnel) -> router (log / notify / approval card) -> escalation (Gemini)
-> executor (approve-only, DEMO_MODE dry run, audit log). See service.py for the loop.
"""
import threading
from .service import H
from .routes import blueprint


def start(scanners):
    """Start the background service. `scanners` maps name -> fn(findings_list)."""
    H.start(scanners)


def submit_scan(findings):
    """Feed findings from a manual scan into the triage queue without blocking the request."""
    threading.Thread(target=H.submit_findings, args=(list(findings), "manual"), daemon=True).start()
