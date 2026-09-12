# 🔒 E2EE Chat

An end-to-end encrypted chat app with two complementary features:

1. **Quick Rooms** — ad-hoc, code-based 1:1 sessions: live text, emoji, files, voice/video messages, and video calls, fully peer-to-peer over WebRTC. No account data involved in the encryption at all.
2. **Messages** — persistent, WhatsApp/Telegram-style messaging by username. Find anyone by their username, message them even if they're offline, and it's still end-to-end encrypted — the server stores ciphertext it cannot read, and auto-deletes it after a configurable window.

Login is by **username + phone number + password** — no OTP, no SMS gateway, no per-message cost.

## How the security actually works

### Quick Rooms (unchanged from the original design)
Each browser generates a throwaway ECDH keypair when it opens a room. Only public keys pass through the server; both browsers derive an identical AES-256-GCM key locally via ECDH. All content is encrypted before it leaves the browser and travels peer-to-peer over WebRTC — the server is a matchmaker only (it relays WebRTC handshake data), never a party to the content.

### Messages — the harder problem, solved properly
Quick Rooms' scheme only works because both people are online at the same time. Messages has to work when the recipient is **offline**, which means encrypting *to a public key* rather than negotiating a session live. Here's the actual design:

- **On registration**, your browser generates a long-term identity keypair. The public key is stored on the server in plain text (safe — that's the point of asymmetric crypto). The private key is encrypted *in your browser* with a key derived from your password (PBKDF2, 250,000 iterations) before it's ever sent anywhere — the server only ever stores that encrypted blob. It has no way to decrypt it: it never has your password, only a one-way bcrypt hash of it (used purely to verify logins, and mathematically useless for deriving the PBKDF2 key).
- **Logging in on any device** re-derives that same AES key from your password + your stored salt, decrypts the private key locally, and you're back in business — this is how the app supports multiple devices/sessions without ever putting your private key on the server in a readable form.
- **Sending a message** encrypts it twice, both times in your browser: once to the recipient's public key (ECIES — a fresh one-time keypair per message, its private half discarded immediately after use) so they can read it, and once to your *own* public key so you can still see your own sent messages later (without this second copy, senders couldn't decrypt their own outbox — the ephemeral key used for the recipient's copy is gone the moment the message is sent). The server stores and forwards both ciphertexts; it can decrypt neither.
- **Real-time delivery**: if the recipient is online, the server also pushes the (still-encrypted) message to them instantly over Socket.IO. If they're offline, it's waiting in their inbox for whenever they next log in.

This whole scheme (PBKDF2 password-wrapping + ECIES) was validated end-to-end before being wired into the UI: a full round trip (register → offline message → login-and-decrypt) works, a simulated attacker without the private key cannot decrypt, and a wrong password cannot recover the key. See the "What I tested" note at the bottom for specifics.

### Message retention & deletion
- Messages are **auto-deleted** after `MESSAGE_RETENTION_DAYS` (default 45, configurable 30-60+ in `.env`) via a MongoDB TTL index — this is real deletion, the document (ciphertext included) is physically removed from the database, not just hidden.
- **Delete for me**: hides a message from your own inbox only; the other person keeps their copy.
- **Delete for everyone**: either person (sender *or* recipient — not just the sender, unlike some apps) can erase a message outright, any time. This actually deletes the database record, so the ciphertext is gone for good, not just hidden behind a flag.

### What the server can still see
Being upfront about this, as before: usernames talking to each other, timestamps, and (for Quick Rooms) IP addresses needed for WebRTC connection setup. It cannot see message text, emoji, filenames, file contents, images, audio, video, or your password/private keys in any form.

## Setup

Requires Node.js 18+ and MongoDB (local install, or a free [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) cluster).

```bash
npm install
cp .env.example .env    # edit if your MongoDB isn't on localhost:27017
npm start
```

Open `http://localhost:3000` — you'll land on the login page.

## Creating an account & logging in

1. Click **"Create an account"**, pick a username (3-20 chars: lowercase letters, numbers, underscore), enter a phone number with country code, and choose a password (8+ characters).
2. Your browser generates your encryption keys at this point (see above) — this happens before anything is sent to the server.
3. To log in later (same device or a new one), use your username *or* phone number, plus your password. On a device that hasn't unlocked your key this session, you'll be asked for your password once more specifically to decrypt your private key locally — this is normal and is the mechanism that lets your account work across devices without the server ever holding a readable private key.

**There is no password reset.** Since your private key only exists in encrypted form (encrypted with a key derived from your password), forgetting your password means losing access to your encrypted messages permanently — there's no "reset password" flow that could work without breaking that guarantee. This is a real, known trade-off of doing this properly; if you want a recovery mechanism later, it needs to be designed deliberately (e.g. a recovery phrase shown once at signup) rather than bolted on.

## Using Messages

- Search a username in the box at the top — click a result to start (or resume) a conversation with them.
- Existing conversations appear in the list below, most recent first.
- Type and send — delivered live if they're online, waiting in their inbox if not.
- Hover a message bubble and click the trash icon for delete options (for me / for everyone).

## Using Quick Rooms

Click **"💬 Go to Messages"** to switch, or **"📹 Quick Room"** from within Messages to switch back. Quick Rooms works exactly as before: one person clicks "Start a new chat", shares the 6-character room code some other way, the other person joins with it.

## Turning this into an installable app

*(Unchanged from before — see the PWA and Android/Capacitor sections that were already set up. Quick recap:)*

- **PWA**: deploy over HTTPS, open on mobile, "Add to Home Screen" — works immediately, no build step.
- **Android APK**: the `android/` folder is a ready-to-open Capacitor project (custom icon, camera/mic permissions, and CORS already configured). Set `SERVER_URL` in `public/config.js` to your deployed backend, run `npm run android:sync`, then open `android/` in Android Studio and **Build → Build APK(s)**. I couldn't compile an actual `.apk` in the sandbox this was built in (no Android SDK / no network access to Google's Maven repos there) — that step needs Android Studio on your machine.

## Project structure

```
server.js                Express + Socket.IO: mounts all routes, gates sockets by session token,
                          joins each authenticated socket to a room named after their username
                          (for real-time message delivery)
config/db.js              MongoDB connection
models/User.js            username, phoneNumber, passwordHash, publicKey, encryptedPrivateKey
models/Message.js         Dual-encrypted messages (forSender/forRecipient), TTL auto-expiry
routes/auth.js             POST /register, POST /login, GET /me (password hashing, rate-limited)
routes/users.js             GET /search?q=, GET /:username — find people by username
routes/messages.js          POST /send, GET /inbox, DELETE /:id — all ciphertext in/out
utils/token.js              JWT sign/verify for session tokens
middleware/authMiddleware.js  Express middleware protecting the above routes
public/
  login.html, login.js       Register/login — generates & password-wraps identity keys client-side
  messages.html/.js/.css     The WhatsApp-style messaging UI
  index.html, app.js         Quick Rooms UI (unchanged)
  crypto.js                  All encryption: both the Quick Rooms scheme AND the
                              password-wrapping / ECIES scheme used by Messages
  webrtc.js                  WebRTC peer connection (Quick Rooms only)
  config.js                  SERVER_URL — see the Android section for why this matters
```

## Limitations / things to know

- This is a solid, real implementation of both encryption schemes described above — but neither has been through a professional security audit. For anything genuinely high-stakes, use an audited tool (Signal) instead of a custom one.
- **No password reset**, by design — see above. Make sure users understand this.
- **No group chat** — Messages is 1:1 only. Extending the ECIES scheme to groups (encrypting to multiple public keys, or a proper sender-key/ratchet scheme like Signal's) is a meaningfully bigger design problem than what's here.
- **No forward secrecy between messages** — each message uses a fresh ephemeral keypair (so a single message's key compromise doesn't expose others), but there's no Double-Ratchet-style continuous re-keying like Signal. Reasonable for a project like this; worth knowing if you're evaluating it against Signal specifically.
- The decrypted private key lives in `sessionStorage` for the browser tab's lifetime (cleared on tab close) rather than being re-requested every single action — a deliberate, common trade-off between security and usability. It is never written to `localStorage` or anywhere persistent in unencrypted form.
- Quick Rooms' large file/video transfer speed still depends on both people's upload bandwidth (true P2P, no server relay for that feature).

## What I tested

Since I can't run a real MongoDB or a real browser in the sandbox this was built in, here's exactly what was and wasn't verified directly:

- **Verified**: the full password-wrap + ECIES scheme end-to-end in Node's WebCrypto implementation (register → offline-encrypt → login-and-decrypt → matches original; wrong password correctly fails to recover the key; an attacker without the private key correctly fails to decrypt) — this is the part where a subtle bug would be most costly, so it got the most scrutiny.
- **Verified**: bcrypt password hashing round-trips correctly; all new backend routes reject malformed/missing input with proper 400s *before* touching the database; every protected route correctly returns 401 without a valid token; the server starts and every static asset (including all the new Messages files) serves correctly; the server fails over gracefully (clear error, no crash) when MongoDB is unreachable; Socket.IO's auth gate accepts valid tokens and rejects missing/garbage ones, for both the old phone-based and new username-based token shapes.
- **Not verified** (no real MongoDB available in this sandbox): the actual register → login → send-message → receive-message flow against a live database. Do that first thing after `npm install` on your machine, with `mongod` running, before relying on it.
