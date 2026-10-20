// Moved out of login.html so the page can run under a strict Content-Security-Policy (no inline scripts).
import { ICONS } from "./icons.js";
document.getElementById("brandMark").innerHTML = ICONS.lock;
