// Applies the colour theme the user picked (light or dark) before the page
// renders, so it doesn't flash. Without a choice the system setting applies.
// Loaded in <head> without defer on purpose; the switch itself is in app.js.
"use strict";
(function () {
  const theme = localStorage.getItem("platypus-theme");
  if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
})();
