"""
Tests for core/siem_forwarder.py.

Uses a real local http.server.HTTPServer (not a mocked requests.post) so
the test actually exercises an HTTP round trip - this is how the Splunk
HEC and Elasticsearch bulk payload shapes were verified for real during
development (see docs/ROADMAP.md), just made deterministic/repeatable
here instead of a manual one-off script.
"""

import json
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core import audit_logger, siem_forwarder


class _RecordingHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.server.received.append({
            "path": self.path,
            "headers": dict(self.headers),
            "body": body.decode("utf-8", errors="replace"),
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, fmt, *args):
        pass  # keep test output quiet


@pytest.fixture
def mock_http_server():
    server = HTTPServer(("127.0.0.1", 0), _RecordingHandler)
    server.received = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    yield f"http://127.0.0.1:{port}", server.received
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def _reset_forwarder(monkeypatch):
    monkeypatch.delenv("WIPERX_SPLUNK_HEC_URL", raising=False)
    monkeypatch.delenv("WIPERX_SPLUNK_HEC_TOKEN", raising=False)
    monkeypatch.delenv("WIPERX_ELASTIC_URL", raising=False)
    siem_forwarder.reset_for_tests()
    yield
    siem_forwarder.reset_for_tests()


def _wait_for(received, count=1, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if len(received) >= count:
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {count} request(s), got {len(received)}")


class TestConfiguration:
    def test_not_configured_by_default(self):
        assert siem_forwarder.is_configured() is False

    def test_splunk_needs_both_url_and_token(self, monkeypatch):
        monkeypatch.setenv("WIPERX_SPLUNK_HEC_URL", "http://example.com")
        assert siem_forwarder.splunk_configured() is False
        monkeypatch.setenv("WIPERX_SPLUNK_HEC_TOKEN", "tok")
        assert siem_forwarder.splunk_configured() is True

    def test_elastic_needs_only_url(self, monkeypatch):
        monkeypatch.setenv("WIPERX_ELASTIC_URL", "http://example.com")
        assert siem_forwarder.elastic_configured() is True

    def test_forward_event_noop_when_unconfigured(self, mock_http_server):
        base_url, received = mock_http_server
        siem_forwarder.forward_event({"event": "should_not_be_sent"})
        time.sleep(0.3)
        assert received == []


class TestRealHttpDelivery:
    def test_splunk_hec_payload_shape(self, monkeypatch, mock_http_server):
        base_url, received = mock_http_server
        monkeypatch.setenv("WIPERX_SPLUNK_HEC_URL", f"{base_url}/services/collector/event")
        monkeypatch.setenv("WIPERX_SPLUNK_HEC_TOKEN", "my-token")

        siem_forwarder.forward_event({
            "timestamp": "2026-09-01T00:00:00Z", "event": "wipe.done",
            "host": "kali", "data": {"disk": "sdb"},
        })
        _wait_for(received)

        req = received[0]
        assert req["path"] == "/services/collector/event"
        assert req["headers"]["Authorization"] == "Splunk my-token"
        body = json.loads(req["body"])
        assert body["event"]["event"] == "wipe.done"
        assert body["event"]["data"] == {"disk": "sdb"}
        assert body["sourcetype"] == "wiperx:audit"

    def test_elasticsearch_bulk_payload_shape(self, monkeypatch, mock_http_server):
        base_url, received = mock_http_server
        monkeypatch.setenv("WIPERX_ELASTIC_URL", base_url)
        monkeypatch.setenv("WIPERX_ELASTIC_INDEX", "my-audit-index")

        siem_forwarder.forward_event({"event": "erase.done", "host": "kali"})
        _wait_for(received)

        req = received[0]
        assert req["path"] == "/_bulk"
        assert req["headers"]["Content-Type"] == "application/x-ndjson"
        lines = req["body"].strip().splitlines()
        assert len(lines) == 2
        action = json.loads(lines[0])
        source = json.loads(lines[1])
        assert action == {"index": {"_index": "my-audit-index"}}
        assert source["event"] == "erase.done"

    def test_both_targets_receive_the_same_event(self, monkeypatch, mock_http_server):
        base_url, received = mock_http_server
        monkeypatch.setenv("WIPERX_SPLUNK_HEC_URL", f"{base_url}/hec")
        monkeypatch.setenv("WIPERX_SPLUNK_HEC_TOKEN", "tok")
        monkeypatch.setenv("WIPERX_ELASTIC_URL", base_url)

        siem_forwarder.forward_event({"event": "recovery.done"})
        _wait_for(received, count=2)

        paths = {r["path"] for r in received}
        assert paths == {"/hec", "/_bulk"}

    def test_log_event_forwards_when_configured(self, monkeypatch, mock_http_server):
        """audit_logger.log_event() itself should reach the SIEM forwarder,
        not just forward_event() called directly."""
        base_url, received = mock_http_server
        monkeypatch.setenv("WIPERX_ELASTIC_URL", base_url)

        audit_logger.log_event("integration_test_event", {"k": "v"})
        _wait_for(received)

        source = json.loads(received[0]["body"].strip().splitlines()[1])
        assert source["event"] == "integration_test_event"
        assert source["data"] == {"k": "v"}


class TestGracefulDegradation:
    def test_unreachable_target_does_not_raise_or_block(self, monkeypatch):
        monkeypatch.setenv("WIPERX_SPLUNK_HEC_URL", "http://127.0.0.1:1/unreachable")
        monkeypatch.setenv("WIPERX_SPLUNK_HEC_TOKEN", "tok")

        start = time.perf_counter()
        siem_forwarder.forward_event({"event": "x"})  # enqueue only, must return fast
        elapsed = time.perf_counter() - start
        assert elapsed < 0.5  # queuing must not wait on the network

    def test_queue_full_drops_without_raising(self, monkeypatch):
        monkeypatch.setenv("WIPERX_ELASTIC_URL", "http://127.0.0.1:1")

        class _AlwaysFullQueue:
            def put_nowait(self, item):
                raise queue.Full

            def empty(self):
                return True  # so reset_for_tests()'s teardown drain is a no-op

        monkeypatch.setattr(siem_forwarder, "_queue", _AlwaysFullQueue())
        monkeypatch.setattr(siem_forwarder, "_ensure_worker_started", lambda: None)

        siem_forwarder.forward_event({"event": "dropped"})  # must not raise
        assert siem_forwarder._dropped_count == 1
