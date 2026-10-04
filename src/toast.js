// OG Boosting global toast notifications
(function () {
  function ensureContainer() {
    let container = document.getElementById("ogToastContainer");
    if (!container) {
      container = document.createElement("div");
      container.id = "ogToastContainer";
      container.setAttribute("aria-live", "polite");
      container.setAttribute("aria-atomic", "true");
      document.body.appendChild(container);
    }
    return container;
  }

  window.showToast = function (message, type = "info", options = {}) {
    const container = ensureContainer();
    const toast = document.createElement("div");
    const titles = {
      success: "Success",
      error: "Something went wrong",
      warning: "Please check",
      info: "OG Boosting"
    };
    const icons = { success: "✓", error: "!", warning: "!", info: "i" };
    const duration = Number(options.duration || 4200);

    toast.className = `og-toast og-toast--${type}`;
    toast.innerHTML = `
      <div class="og-toast__icon">${icons[type] || icons.info}</div>
      <div class="og-toast__content">
        <p class="og-toast__title">${options.title || titles[type] || titles.info}</p>
        <p class="og-toast__message"></p>
      </div>
      <button type="button" class="og-toast__close" aria-label="Close notification">&times;</button>
    `;
    toast.querySelector(".og-toast__message").textContent = String(message || "");
    container.appendChild(toast);

    requestAnimationFrame(() => toast.classList.add("is-visible"));

    const remove = () => {
      if (toast.dataset.removing) return;
      toast.dataset.removing = "1";
      toast.classList.remove("is-visible");
      toast.classList.add("is-leaving");
      setTimeout(() => toast.remove(), 300);
    };

    toast.querySelector(".og-toast__close").addEventListener("click", remove);
    setTimeout(remove, duration);
    return remove;
  };
})();
