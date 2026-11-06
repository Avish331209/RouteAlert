/**
 * main.js - RouteAlert Client-side enhancements
 * Lightweight, vanilla JavaScript for Salem Bus Delay and Route Diversion Alert System.
 */

document.addEventListener("DOMContentLoaded", function () {
  // 1. Flash alert message dismissal
  const closeButtons = document.querySelectorAll(".close-alert");
  closeButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      const alertMsg = this.closest(".alert-msg");
      if (alertMsg) {
        alertMsg.style.transition = "opacity 0.25s ease, transform 0.25s ease";
        alertMsg.style.opacity = "0";
        alertMsg.style.transform = "translateY(-5px)";
        setTimeout(function () {
          alertMsg.remove();
        }, 250);
      }
    });
  });

  // 2. Action confirmation prompts for admin lifecycle state changes
  const confirmForms = document.querySelectorAll("form[data-confirm]");
  confirmForms.forEach(function (form) {
    form.addEventListener("submit", function (e) {
      const message = form.getAttribute("data-confirm") || "Are you sure you want to proceed?";
      if (!window.confirm(message)) {
        e.preventDefault();
      }
    });
  });

  // 3. Clear filters helper
  const clearFilterBtn = document.getElementById("clear-filters-btn");
  if (clearFilterBtn) {
    clearFilterBtn.addEventListener("click", function (e) {
      e.preventDefault();
      window.location.href = window.location.pathname;
    });
  }
});
