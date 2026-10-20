/**
 * menu.js — a small dropdown ("3-dot") menu where every item has an icon AND
 * a text label, so nobody has to guess what an icon means.
 *
 *   attachMenu(buttonEl, () => [
 *     { label: "Settings", icon: ICONS.settings, href: "settings.html" },
 *     { label: "Log out",  icon: ICONS.logout, danger: true, onClick: logout },
 *   ]);
 *
 * Items are re-read every time the menu opens (so labels can change, e.g.
 * "Block @sam" / "Unblock @sam").
 */
let openMenu = null; // { el, btn }

export function closeMenus() {
  if (!openMenu) return false;
  openMenu.el.remove();
  openMenu.btn.setAttribute("aria-expanded", "false");
  openMenu = null;
  return true;
}

export function isMenuOpen() {
  return !!openMenu;
}

export function attachMenu(btn, getItems) {
  btn.setAttribute("aria-haspopup", "menu");
  btn.setAttribute("aria-expanded", "false");

  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    if (openMenu && openMenu.btn === btn) return void closeMenus();
    closeMenus();

    const el = document.createElement("div");
    el.className = "dropdown";
    el.setAttribute("role", "menu");

    for (const item of getItems()) {
      if (!item) continue;
      const row = document.createElement(item.href ? "a" : "button");
      row.className = "dropdown-item" + (item.danger ? " danger" : "");
      row.setAttribute("role", "menuitem");
      if (item.href) row.href = item.href;
      row.innerHTML = `<span class="dropdown-icon">${item.icon || ""}</span><span class="dropdown-label"></span>`;
      row.querySelector(".dropdown-label").textContent = item.label;
      row.addEventListener("click", () => {
        closeMenus();
        item.onClick?.();
      });
      el.appendChild(row);
    }

    document.body.appendChild(el);
    // Place under the button, kept inside the screen.
    const r = btn.getBoundingClientRect();
    const w = el.offsetWidth;
    el.style.top = `${Math.round(r.bottom + 6)}px`;
    el.style.left = `${Math.max(8, Math.min(window.innerWidth - w - 8, r.right - w))}px`;
    btn.setAttribute("aria-expanded", "true");
    openMenu = { el, btn };
  });
}

document.addEventListener("click", (e) => {
  if (openMenu && !openMenu.el.contains(e.target)) closeMenus();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeMenus();
});
window.addEventListener("resize", closeMenus);
