# wiperx/core/siem_forwarder.py
"""
SIEM Forwarder
--------------
Best-effort, non-blocking forwarding of audit events to Splunk (HTTP
Event Collector) and/or Elasticsearch/OpenSearch (bulk API).

Disabled by default: forward_event() is a no-op unless at least one
target is configured via environment variables, so audit_logger.py's
behavior (and every existing test) is unaffected when neither is set.

Design: a single daemon worker thread drains a bounded queue and does the
actual HTTP POSTs, so a slow or unreachable SIEM never adds latency to
the wipe/erase/recovery operation that triggered the audit event - the
same "never let telemetry become a blocker" posture as the rest of this
codebase (blkdiscard failures, SMART checks, etc. are all non-fatal).
Delivery is best-effort: if the queue is full (SIEM down for a while),
new events are dropped with a warning rather than blocking or growing
unbounded.

Configuration (environment variables):
    WIPERX_SPLUNK_HEC_URL         e.g. https://splunk.example.com:8088/services/collector/event
    WIPERX_SPLUNK_HEC_TOKEN       HEC token
    WIPERX_SPLUNK_HEC_SOURCETYPE  default "wiperx:audit"
    WIPERX_SPLUNK_HEC_VERIFY_SSL  default "true"

    WIPERX_ELASTIC_URL            e.g. https://es.example.com:9200
    WIPERX_ELASTIC_INDEX          default "wiperx-audit"
    WIPERX_ELASTIC_API_KEY        Elastic API key (Authorization: ApiKey ...), or
    WIPERX_ELASTIC_USERNAME / WIPERX_ELASTIC_PASSWORD   basic auth, or neither (open cluster)
    WIPERX_ELASTIC_VERIFY_SSL     default "true"
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import requests

    _REQUESTS_OK = True
except ImportError:  # pragma: no cover - dependency is declared in requirements.txt
    _REQUESTS_OK = False

_QUEUE_MAXSIZE = 1000
_HTTP_TIMEOUT_S = 5

_queue: "queue.Queue[dict]" = queue.Queue(maxsize=_QUEUE_MAXSIZE)
_worker: Optional[threading.Thread] = None
_worker_lock = threading.Lock()
_dropped_count = 0


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _bool_env(name: str, default: bool = True) -> bool:
    return _env(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def splunk_configured() -> bool:
    return bool(_env("WIPERX_SPLUNK_HEC_URL") and _env("WIPERX_SPLUNK_HEC_TOKEN"))


def elastic_configured() -> bool:
    return bool(_env("WIPERX_ELASTIC_URL"))


def is_configured() -> bool:
    return splunk_configured() or elastic_configured()


def forward_event(entry: dict) -> None:
    """
    Enqueue an audit-log entry (same dict shape audit_logger.py writes to
    the JSON Lines file) for best-effort delivery to configured SIEM
    targets. Never raises, never blocks the caller beyond a queue.put_nowait.
    """
    if not is_configured() or not _REQUESTS_OK:
        return

    _ensure_worker_started()
    try:
        _queue.put_nowait(dict(entry))
    except queue.Full:
        global _dropped_count
        _dropped_count += 1
        if _dropped_count == 1 or _dropped_count % 100 == 0:
            logger.warning(
                "[siem_forwarder] queue full (%d dropped total) - SIEM target(s) "
                "unreachable or too slow", _dropped_count,
            )


def _ensure_worker_started() -> None:
    global _worker
    with _worker_lock:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_worker_loop, name="wiperx-siem-forwarder", daemon=True)
            _worker.start()


def _worker_loop() -> None:
    while True:
        entry = _queue.get()
        try:
            if splunk_configured():
                _send_splunk(entry)
            if elastic_configured():
                _send_elastic(entry)
        except Exception as exc:  # noqa: BLE001 - a forwarding failure must never kill the worker
            logger.warning("[siem_forwarder] delivery failed: %s", exc)
        finally:
            _queue.task_done()


def _send_splunk(entry: dict) -> None:
    url = _env("WIPERX_SPLUNK_HEC_URL")
    token = _env("WIPERX_SPLUNK_HEC_TOKEN")
    sourcetype = _env("WIPERX_SPLUNK_HEC_SOURCETYPE", "wiperx:audit")
    verify = _bool_env("WIPERX_SPLUNK_HEC_VERIFY_SSL", True)

    payload = {
        "event": entry,
        "sourcetype": sourcetype,
        "host": entry.get("host", ""),
    }
    resp = requests.post(
        url,
        headers={"Authorization": f"Splunk {token}"},
        data=json.dumps(payload),
        timeout=_HTTP_TIMEOUT_S,
        verify=verify,
    )
    if resp.status_code >= 300:
        logger.warning("[siem_forwarder] Splunk HEC returned %s: %s", resp.status_code, resp.text[:300])


def _send_elastic(entry: dict) -> None:
    base_url = _env("WIPERX_ELASTIC_URL").rstrip("/")
    index = _env("WIPERX_ELASTIC_INDEX", "wiperx-audit")
    verify = _bool_env("WIPERX_ELASTIC_VERIFY_SSL", True)

    headers = {"Content-Type": "application/x-ndjson"}
    api_key = _env("WIPERX_ELASTIC_API_KEY")
    auth = None
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    else:
        user = _env("WIPERX_ELASTIC_USERNAME")
        pw = _env("WIPERX_ELASTIC_PASSWORD")
        if user and pw:
            auth = (user, pw)

    # Bulk API, one document: action line + source line, each newline-terminated.
    action = json.dumps({"index": {"_index": index}})
    source = json.dumps(entry)
    body = f"{action}\n{source}\n"

    resp = requests.post(
        f"{base_url}/_bulk",
        headers=headers,
        data=body,
        auth=auth,
        timeout=_HTTP_TIMEOUT_S,
        verify=verify,
    )
    if resp.status_code >= 300:
        logger.warning("[siem_forwarder] Elasticsearch bulk API returned %s: %s",
                        resp.status_code, resp.text[:300])
    elif resp.status_code == 200:
        try:
            if resp.json().get("errors"):
                logger.warning("[siem_forwarder] Elasticsearch bulk API reported item errors: %s",
                                resp.text[:300])
        except ValueError:
            pass


def reset_for_tests() -> None:
    """Drain the queue and forget the worker thread - used only by tests."""
    global _worker, _dropped_count
    while not _queue.empty():
        try:
            _queue.get_nowait()
            _queue.task_done()
        except queue.Empty:
            break
    _worker = None
    _dropped_count = 0
