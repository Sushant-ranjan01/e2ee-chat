// Moved out of settings.html so the page can run under a strict Content-Security-Policy (no inline scripts).
import { ICONS } from "./icons.js";
document.getElementById("backLink").innerHTML = ICONS.back + '<span class="hb-text">Back</span>';
document.getElementById("blockAddBtn").innerHTML = ICONS.block + " Block";
document.getElementById("logoutBtn").innerHTML = ICONS.logout + " Log out";
document.getElementById("eraseLocalBtn").innerHTML = ICONS.trash + " Erase messages on this device";
document.getElementById("testNotifBtn").innerHTML = ICONS.chat + " Send a test notification";
