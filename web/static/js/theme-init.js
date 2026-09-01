/* Runs synchronously in <head> before first paint — no FOUC.
 * Theme precedence: explicit localStorage choice > OS preference. */
(function () {
  try {
    var t = localStorage.getItem("wx-theme");
    if (t === "light" || t === "dark") {
      document.documentElement.setAttribute("data-theme", t);
    }
  } catch (e) {
    /* private mode / disabled storage — fall back to OS via CSS media query */
  }
})();
