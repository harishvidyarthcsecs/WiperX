/* WiperX web — vanilla JS (no framework, CSP-friendly: script-src 'self').
 * Behaviour is wired via data-* attributes and event delegation. */
(function () {
  "use strict";

  var root = document.documentElement;

  function resolvedTheme() {
    var explicit = null;
    try {
      explicit = localStorage.getItem("wx-theme");
    } catch (e) {}
    if (explicit === "light" || explicit === "dark") return explicit;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function syncThemeButtons() {
    var dark = resolvedTheme() === "dark";
    document.querySelectorAll("[data-wx-theme-toggle]").forEach(function (btn) {
      btn.querySelectorAll("[data-when]").forEach(function (el) {
        var want = el.getAttribute("data-when");
        el.hidden = want === "dark" ? !dark : dark;
      });
    });
  }

  function toggleTheme() {
    var next = resolvedTheme() === "dark" ? "light" : "dark";
    try {
      localStorage.setItem("wx-theme", next);
    } catch (e) {}
    root.setAttribute("data-theme", next);
    syncThemeButtons();
  }

  function openSidebar(open) {
    var aside = document.querySelector("[data-wx-sidebar]");
    var scrim = document.querySelector("[data-wx-scrim]");
    if (!aside) return;
    aside.classList.toggle("wx-sidebar-open", open);
    if (scrim) scrim.hidden = !open;
  }

  document.addEventListener("click", function (ev) {
    var t = ev.target.closest(
      "[data-wx-theme-toggle],[data-wx-sidebar-toggle],[data-wx-sidebar-close],[data-wx-scrim],[data-wx-copy],[data-wx-confirm-open],[data-wx-confirm-cancel]"
    );
    if (!t) return;

    if (t.hasAttribute("data-wx-theme-toggle")) {
      toggleTheme();
    } else if (t.hasAttribute("data-wx-sidebar-toggle")) {
      var aside = document.querySelector("[data-wx-sidebar]");
      openSidebar(!(aside && aside.classList.contains("wx-sidebar-open")));
    } else if (t.hasAttribute("data-wx-sidebar-close") || t.hasAttribute("data-wx-scrim")) {
      openSidebar(false);
    } else if (t.hasAttribute("data-wx-copy")) {
      var val = t.getAttribute("data-wx-copy");
      if (navigator.clipboard) {
        navigator.clipboard.writeText(val).then(function () {
          var old = t.getAttribute("aria-label");
          t.setAttribute("aria-label", "Copied");
          setTimeout(function () {
            t.setAttribute("aria-label", old || "Copy");
          }, 1200);
        });
      }
    } else if (t.hasAttribute("data-wx-confirm-open")) {
      var dlg = document.getElementById(t.getAttribute("data-wx-confirm-open"));
      if (dlg) dlg.hidden = false;
    } else if (t.hasAttribute("data-wx-confirm-cancel")) {
      var d = t.closest("[data-wx-confirm]");
      if (d) {
        d.hidden = true;
        var inp = d.querySelector("[data-wx-confirm-input]");
        if (inp) inp.value = "";
        syncConfirm(d);
      }
    }
  });

  // Confirm dialog: enable the submit button only when the typed phrase matches.
  function syncConfirm(dlg) {
    var input = dlg.querySelector("[data-wx-confirm-input]");
    var submit = dlg.querySelector("[data-wx-confirm-submit]");
    if (!submit) return;
    var phrase = dlg.getAttribute("data-wx-confirm-phrase") || "";
    submit.disabled = phrase ? !input || input.value.trim() !== phrase : false;
  }
  document.addEventListener("input", function (ev) {
    if (ev.target.matches("[data-wx-confirm-input]")) {
      var dlg = ev.target.closest("[data-wx-confirm]");
      if (dlg) syncConfirm(dlg);
    }
  });

  // Machine registration: show SSH or WinRM field group based on the select.
  function syncConnFields(sel) {
    var scope = sel.closest("form") || document;
    var kind = sel.value;
    scope.querySelectorAll("[data-wx-conn-ssh]").forEach(function (el) {
      el.hidden = kind !== "ssh";
    });
    scope.querySelectorAll("[data-wx-conn-winrm]").forEach(function (el) {
      el.hidden = kind !== "winrm";
    });
  }
  document.addEventListener("change", function (ev) {
    if (ev.target.matches("[data-wx-conn]")) syncConnFields(ev.target);
  });

  // Machine connectivity test (AJAX; endpoint returns JSON {status,message}).
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-wx-test-conn]");
    if (!btn) return;
    var url = btn.getAttribute("data-wx-test-conn");
    var badge = document.getElementById(btn.getAttribute("data-target"));
    if (badge) {
      badge.textContent = "testing…";
      badge.className = "wx-badge wx-badge-untrusted";
    }
    fetch(url)
      .then(function (r) {
        return r.json();
      })
      .then(function (data) {
        if (!badge) return;
        var online = data.status === "online";
        badge.textContent = data.status;
        badge.className = "wx-badge " + (online ? "wx-badge-verified" : "wx-badge-unsigned");
        badge.title = data.message || "";
      })
      .catch(function () {
        if (badge) {
          badge.textContent = "error";
          badge.className = "wx-badge wx-badge-unsigned";
        }
      });
  });

  document.addEventListener("DOMContentLoaded", function () {
    syncThemeButtons();
    document.querySelectorAll("[data-wx-conn]").forEach(syncConnFields);
    document.querySelectorAll("[data-wx-confirm]").forEach(syncConfirm);
  });

  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", syncThemeButtons);
})();
