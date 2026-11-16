// Mark that JavaScript runs, so the static (crawler) copy of the page stays hidden.
document.documentElement.classList.add('js');
/* Apply the saved theme before first paint (kept external so the CSP needs no 'unsafe-inline' for scripts). */
try {
  var t = localStorage.getItem('se-theme');
  if (t) document.documentElement.dataset.theme = t;
} catch (e) { /* storage unavailable */ }
