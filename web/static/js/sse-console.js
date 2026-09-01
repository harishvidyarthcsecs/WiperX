/* WiperX SSE log console — vanilla, CSP-friendly. One implementation for both the
 * drive-wipe and the recovery run screens. Server contract unchanged:
 *   POST <data-start-url>               -> { status: "started" } | { error }
 *   GET  <data-stream-url> (EventSource) -> data: {type:"log"|"heartbeat"|"done", ...}
 *
 * Markup:
 *   <div data-wx-console data-start-url="…" data-stream-url="…" data-kind="wipe">
 *     <div data-wx-status>…</div>
 *     <div data-wx-log class="wx-console"></div>
 *     <div data-wx-result hidden></div>
 *   </div>
 */
(function () {
  "use strict";

  function classify(line) {
    var s = (line || "").toUpperCase();
    if (/\b(ERROR|BLOCK|FAIL|FATAL|DENIED)\b/.test(s)) return "ln-error";
    if (/\b(WARN|WARNING|SKIP)\b/.test(s)) return "ln-warning";
    if (/\b(OK|DONE|SUCCESS|COMPLETE|VERIFIED|SIGNED)\b/.test(s)) return "ln-success";
    if (/^\[/.test(line || "")) return "ln-info";
    return "ln-muted";
  }

  function csrfToken() {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.getAttribute("content") : "";
  }

  function init(box) {
    var startUrl = box.getAttribute("data-start-url");
    var streamUrl = box.getAttribute("data-stream-url");
    var kind = box.getAttribute("data-kind") || "operation";
    var logEl = box.querySelector("[data-wx-log]");
    var statusEl = box.querySelector("[data-wx-status]");
    var resultEl = box.querySelector("[data-wx-result]");
    var es = null;

    function setStatus(text, variant) {
      if (!statusEl) return;
      statusEl.textContent = text;
      statusEl.setAttribute("data-state", variant || "");
    }

    function append(text) {
      if (!logEl) return;
      var line = document.createElement("div");
      line.className = classify(text);
      line.textContent = text;
      logEl.appendChild(line);
      logEl.scrollTop = logEl.scrollHeight;
    }

    function finish(msg) {
      var ok = !!msg.success;
      setStatus(ok ? "Complete" : "Failed", ok ? "done" : "error");
      append(ok ? "[client] " + kind + " complete." : "[client] " + kind + " failed: " + (msg.error || "unknown error"));
      if (resultEl) {
        resultEl.hidden = false;
        resultEl.dispatchEvent(new CustomEvent("wx:done", { detail: msg }));
      }
      if (es) {
        es.close();
        es = null;
      }
    }

    function connect() {
      es = new EventSource(streamUrl);
      es.onmessage = function (ev) {
        var msg;
        try {
          msg = JSON.parse(ev.data);
        } catch (e) {
          return;
        }
        if (msg.type === "heartbeat") return;
        if (msg.type === "log") return append(msg.message || "");
        if (msg.type === "done") return finish(msg);
      };
      es.onerror = function () {
        append("[client] stream interrupted — retrying…");
      };
    }

    async function run() {
      setStatus("Running", "running");
      append("[client] starting " + kind + "…");
      try {
        var resp = await fetch(startUrl, { method: "POST", headers: { "X-CSRFToken": csrfToken() } });
        var body = await resp.json().catch(function () {
          return {};
        });
        if (!resp.ok || body.error) {
          setStatus("Failed", "error");
          append("[client] could not start: " + (body.error || resp.status));
          return;
        }
      } catch (e) {
        setStatus("Failed", "error");
        append("[client] request failed: " + e);
        return;
      }
      connect();
    }

    window.addEventListener("beforeunload", function () {
      if (es) es.close();
    });

    run();
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-wx-console]").forEach(init);
  });
})();
