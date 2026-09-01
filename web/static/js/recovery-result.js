/* Rewrites the "Open case" link once the recovery SSE stream reports done. */
(function () {
  "use strict";
  document.addEventListener("DOMContentLoaded", function () {
    var box = document.querySelector("[data-wx-result]");
    if (!box) return;
    var tmpl = box.getAttribute("data-case-url-template") || "";
    box.addEventListener("wx:done", function (ev) {
      var msg = ev.detail || {};
      var link = box.querySelector("[data-wx-open-case]");
      if (link && msg.case_name && tmpl) {
        link.setAttribute("href", tmpl.replace("__NAME__", encodeURIComponent(msg.case_name)));
      }
    });
  });
})();
