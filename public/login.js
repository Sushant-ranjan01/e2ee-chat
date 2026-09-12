import { SERVER_URL } from "./config.js";
import {
  generateIdentityKeyPair,
  deriveKeyFromPassword,
  wrapPrivateKey,
  unwrapPrivateKey,
  exportIdentityPublicKey,
} from "./crypto.js";

const $ = (id) => document.getElementById(id);

// Already logged in (have a session token)? Skip straight to Messages —
// messages.js will prompt for the password again there ONLY if this tab
// doesn't already have the private key unlocked in memory.
if (localStorage.getItem("e2ee_token")) {
  window.location.href = "/messages.html";
}

function showError(msg) {
  $("loginError").textContent = msg;
  $("loginStatus").textContent = "";
}
function showStatus(msg) {
  $("loginStatus").textContent = msg;
  $("loginError").textContent = "";
}

$("showRegister").onclick = (e) => {
  e.preventDefault();
  $("loginForm").classList.add("hidden");
  $("registerForm").classList.remove("hidden");
  $("modeSubtitle").textContent = "Create an account to start messaging securely.";
  $("loginError").textContent = "";
};
$("showLogin").onclick = (e) => {
  e.preventDefault();
  $("registerForm").classList.add("hidden");
  $("loginForm").classList.remove("hidden");
  $("modeSubtitle").textContent = "Log in to continue.";
  $("loginError").textContent = "";
};

async function completeLogin({ token, user, publicKey, encryptedPrivateKey }, password) {
  showStatus("Unlocking your encryption key…");
  // Recover this account's private key locally, using the password. The
  // server never sees the password-derived key or the unwrapped private key.
  const { aesKey } = await deriveKeyFromPassword(password, encryptedPrivateKey.salt);
  const privateKey = await unwrapPrivateKey(encryptedPrivateKey, aesKey);
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);

  localStorage.setItem("e2ee_token", token);
  localStorage.setItem("e2ee_username", user.username);
  localStorage.setItem("e2ee_phone", user.phoneNumber);
  localStorage.setItem("e2ee_public_key", publicKey);
  // Kept in sessionStorage (cleared when the tab closes), not localStorage —
  // this is the actual decrypted private key, so it shouldn't outlive the
  // session any more than necessary. Reopening later just means unlocking
  // it again with the password via GET /api/auth/me.
  sessionStorage.setItem("e2ee_privkey_jwk", JSON.stringify(jwk));

  window.location.href = "/messages.html";
}

$("loginBtn").onclick = async () => {
  const identifier = $("loginIdentifier").value.trim();
  const password = $("loginPassword").value;
  if (!identifier || !password) return showError("Enter your username/phone and password.");

  $("loginBtn").disabled = true;
  try {
    showStatus("Logging in…");
    const res = await fetch(`${SERVER_URL}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ identifier, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Login failed.");
    await completeLogin(data, password);
  } catch (err) {
    showError(err.message);
  } finally {
    $("loginBtn").disabled = false;
  }
};

$("registerBtn").onclick = async () => {
  const username = $("regUsername").value.trim().toLowerCase();
  const phoneNumber = $("regPhone").value.trim();
  const password = $("regPassword").value;
  const confirm = $("regPasswordConfirm").value;

  if (!username || !phoneNumber || !password) return showError("Fill in all fields.");
  if (password.length < 8) return showError("Password must be at least 8 characters.");
  if (password !== confirm) return showError("Passwords don't match.");

  $("registerBtn").disabled = true;
  try {
    showStatus("Generating your encryption keys…");
    const keyPair = await generateIdentityKeyPair();
    const publicKey = await exportIdentityPublicKey(keyPair.publicKey);
    const { aesKey, saltB64 } = await deriveKeyFromPassword(password);
    const wrapped = await wrapPrivateKey(keyPair.privateKey, aesKey);
    const encryptedPrivateKey = { ciphertext: wrapped.ciphertext, iv: wrapped.iv, salt: saltB64 };

    showStatus("Creating your account…");
    const res = await fetch(`${SERVER_URL}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, phoneNumber, password, publicKey, encryptedPrivateKey }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Registration failed.");
    await completeLogin(data, password);
  } catch (err) {
    showError(err.message);
  } finally {
    $("registerBtn").disabled = false;
  }
};

[$("loginIdentifier"), $("loginPassword")].forEach((el) =>
  el.addEventListener("keydown", (e) => e.key === "Enter" && $("loginBtn").click())
);
[$("regUsername"), $("regPhone"), $("regPassword"), $("regPasswordConfirm")].forEach((el) =>
  el.addEventListener("keydown", (e) => e.key === "Enter" && $("registerBtn").click())
);
