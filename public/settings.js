import { SERVER_URL } from "./config.js";
import { setBackHandler, unregisterPush, isNative, notificationPreviewOn, setNotificationPreview, notify, initNotifications } from "./native.js";
import { eraseLocalData } from "./keyring.js";
import {
  initAppLock, isLockEnabled, getLockSettings, enableLock, disableLock, changePin, checkPin,
  setLockTimeout, setBiometric, biometricAvailable, isSecureScreenOn, setSecureScreenPref, PIN_REGEX,
} from "./applock.js";

initAppLock();

const $ = (id) => document.getElementById(id);
const token = localStorage.getItem("e2ee_token");
const myUsername = localStorage.getItem("e2ee_username");
if (!token || !myUsername) window.location.href = "/login.html";

$("whoAmI").textContent = "@" + myUsername;

function logout() {
  unregisterPush(); // before the login token is cleared
  localStorage.removeItem("e2ee_token");
  localStorage.removeItem("e2ee_username");
  localStorage.removeItem("e2ee_phone");
  localStorage.removeItem("e2ee_public_key");
  sessionStorage.removeItem("e2ee_privkey_jwk");
  window.location.href = "/login.html";
}
$("logoutBtn").onclick = logout;

async function api(path, options = {}) {
  const res = await fetch(`${SERVER_URL}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, ...(options.headers || {}) },
  });
  if (res.status === 401) return logout();
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function setMsg(id, text, kind = "") {
  const el = $(id);
  el.textContent = text;
  el.className = "settings-msg" + (kind ? " " + kind : "");
}

function render(p) {
  $("showOnlineToggle").checked = p.showOnlineStatus;
  const list = $("blockedList");
  list.innerHTML = "";
  if (p.blocked.length === 0) {
    list.innerHTML = '<div class="blocked-empty">You haven\'t blocked anyone.</div>';
    return;
  }
  for (const name of p.blocked) {
    const row = document.createElement("div");
    row.className = "blocked-row";
    const label = document.createElement("strong");
    label.textContent = "@" + name;
    const btn = document.createElement("button");
    btn.textContent = "Unblock";
    btn.onclick = async () => {
      btn.disabled = true;
      try {
        render(await api("/api/users/unblock", { method: "POST", body: JSON.stringify({ username: name }) }));
        setMsg("blockMsg", `Unblocked @${name}.`, "ok");
      } catch (err) {
        btn.disabled = false;
        setMsg("blockMsg", err.message, "err");
      }
    };
    row.append(label, btn);
    list.appendChild(row);
  }
}

$("showOnlineToggle").addEventListener("change", async (e) => {
  const want = e.target.checked;
  try {
    render(await api("/api/users/me/privacy", { method: "PUT", body: JSON.stringify({ showOnlineStatus: want }) }));
    setMsg("privacyMsg", want ? "Others can now see when you're online." : "Your online status is now hidden from everyone.", "ok");
  } catch (err) {
    e.target.checked = !want;
    setMsg("privacyMsg", err.message, "err");
  }
});

async function addBlock() {
  const username = $("blockInput").value.trim().replace(/^@+/, "").toLowerCase();
  if (!username) return;
  $("blockAddBtn").disabled = true;
  try {
    render(await api("/api/users/block", { method: "POST", body: JSON.stringify({ username }) }));
    $("blockInput").value = "";
    setMsg("blockMsg", `Blocked @${username}.`, "ok");
  } catch (err) {
    setMsg("blockMsg", err.message, "err");
  }
  $("blockAddBtn").disabled = false;
}
$("blockAddBtn").onclick = addBlock;
$("blockInput").addEventListener("keydown", (e) => { if (e.key === "Enter") addBlock(); });

setBackHandler(() => { window.location.replace("messages.html"); return true; });

api("/api/users/me/privacy").then((p) => p && render(p)).catch((err) => setMsg("privacyMsg", err.message, "err"));

// ============================================================
// App lock & screen privacy
// ============================================================
let pinMode = null; // "enable" | "change" | "disable"

function lockMsg(text, kind = "") { setMsg("lockMsg", text, kind); }

async function renderLock() {
  const cfg = getLockSettings();
  $("lockToggle").checked = cfg.enabled;
  $("lockOptions").classList.toggle("hidden", !cfg.enabled);
  $("lockTimeout").value = String(cfg.timeoutSec);
  $("bioToggle").checked = cfg.biometric;
  $("bioRow").classList.toggle("hidden", !(cfg.enabled && (await biometricAvailable())));
  $("secureRow").classList.toggle("hidden", !isNative);
  $("secureToggle").checked = isSecureScreenOn();
}

function openPinForm(mode) {
  pinMode = mode;
  $("pinOld").classList.toggle("hidden", mode === "enable");
  $("pinNew").classList.toggle("hidden", mode === "disable");
  $("pinConfirm").classList.toggle("hidden", mode === "disable");
  for (const id of ["pinOld", "pinNew", "pinConfirm"]) $(id).value = "";
  $("pinSaveBtn").textContent = mode === "disable" ? "Turn off lock" : "Save PIN";
  $("pinForm").classList.remove("hidden");
  lockMsg("");
  (mode === "enable" ? $("pinNew") : $("pinOld")).focus();
}
function closePinForm() {
  pinMode = null;
  $("pinForm").classList.add("hidden");
  renderLock();
}

$("lockToggle").addEventListener("change", (e) => {
  if (e.target.checked) openPinForm("enable");
  else openPinForm("disable");
});
$("changePinBtn").onclick = () => openPinForm("change");
$("pinCancelBtn").onclick = closePinForm;

$("pinSaveBtn").onclick = async () => {
  try {
    const oldPin = $("pinOld").value, newPin = $("pinNew").value, again = $("pinConfirm").value;
    if (pinMode === "disable") {
      await disableLock(oldPin);
      lockMsg("PIN lock is off.", "ok");
    } else {
      if (!PIN_REGEX.test(newPin)) throw new Error("PIN must be 4 to 8 digits.");
      if (newPin !== again) throw new Error("The two PINs don't match.");
      if (pinMode === "change") await changePin(oldPin, newPin);
      else await enableLock(newPin);
      lockMsg(pinMode === "change" ? "PIN changed." : "PIN lock is on.", "ok");
    }
    closePinForm();
  } catch (err) {
    lockMsg(err.message, "err");
  }
};

$("lockTimeout").addEventListener("change", (e) => { setLockTimeout(Number(e.target.value)); lockMsg("Saved.", "ok"); });
$("bioToggle").addEventListener("change", (e) => { setBiometric(e.target.checked); lockMsg("Saved.", "ok"); });
$("secureToggle").addEventListener("change", async (e) => {
  await setSecureScreenPref(e.target.checked);
  lockMsg(e.target.checked ? "Screenshots are blocked." : "Screenshots are allowed.", "ok");
});

renderLock();

// ============================================================
// Erase the local message vault + one-time keys
// ============================================================
$("eraseLocalBtn").onclick = async () => {
  if (!confirm("Erase all messages stored on this device?\n\nMessages the server no longer has will be gone for good. This can't be undone.")) return;
  try {
    await eraseLocalData(myUsername);
    setMsg("eraseMsg", "Done. Local message history and keys were erased. Open Messages to set up fresh keys.", "ok");
  } catch (err) {
    setMsg("eraseMsg", "Couldn't erase: " + err.message, "err");
  }
};

// ============================================================
// Notifications
// ============================================================
$("previewToggle").checked = notificationPreviewOn();
$("previewToggle").addEventListener("change", (e) => {
  setNotificationPreview(e.target.checked);
  setMsg("notifMsg", e.target.checked ? "Notifications will show the message text." : "Notifications will just say \"New message\".", "ok");
});
$("testNotifBtn").onclick = async () => {
  await initNotifications(); // asks for permission the first time (Android 13+)
  await notify({ title: "SecureChat", body: "Notifications are working.", channel: "messages", extra: {} });
  setMsg("notifMsg", "Sent. Lock your phone or switch apps to see it. Nothing showed up? Allow notifications for this app in Android settings.", "ok");
};
