# 🔒 E2EE Chat

An end-to-end encrypted chat app with two complementary features:

1. **Quick Rooms** — ad-hoc, code-based sessions for up to 6 people: live text, emoji, files, voice/video messages, and video calls, fully peer-to-peer over a WebRTC mesh. No account data involved in the encryption at all.
2. **Messages** — persistent, WhatsApp/Telegram-style messaging by username. Find anyone by their username, message them even if they're offline, and it's still end-to-end encrypted — the server stores ciphertext it cannot read, and auto-deletes it after a configurable window.

Login is by **username + phone number + password** — no OTP, no SMS gateway, no per-message cost.

## How the security actually works

### Quick Rooms
Each browser generates ONE throwaway ECDH keypair for the whole room session. With more than 2 people, the room uses a **mesh topology** — every pair of participants opens its own direct WebRTC connection and derives its own independent pairwise AES-256-GCM key (the same keypair is reused for every pairwise ECDH exchange; a different peer's public key naturally produces a different, unrelated shared secret). Sending a text message or file encrypts it separately for each currently-connected peer and sends it over that specific peer's connection. Only public keys and WebRTC handshake data (SDP/ICE) pass through the server, each addressed to a specific peer — never broadcast to the whole room, and never containing content the server could read. Capped at `ROOM_MAX_SIZE` (default 6) people, since a full mesh's connection count grows fast (N people = N×(N-1)/2 total connections).

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

1. Click **"Create an account"**, pick a username (3-20 chars: lowercase letters, numbers, underscore), enter your 10-digit Indian mobile number (the `+91` is applied automatically — just type the digits, validated both in the browser and on the server), and choose a password (8+ characters).
2. Your browser generates your encryption keys at this point (see above) — this happens before anything is sent to the server.
3. To log in later (same device or a new one), use your username *or* phone number, plus your password. On a device that hasn't unlocked your key this session, you'll be asked for your password once more specifically to decrypt your private key locally — this is normal and is the mechanism that lets your account work across devices without the server ever holding a readable private key.

**There is no password reset.** Since your private key only exists in encrypted form (encrypted with a key derived from your password), forgetting your password means losing access to your encrypted messages permanently — there's no "reset password" flow that could work without breaking that guarantee. This is a real, known trade-off of doing this properly; if you want a recovery mechanism later, it needs to be designed deliberately (e.g. a recovery phrase shown once at signup) rather than bolted on.

## More features (v2)

- **Unread badges** on each chat plus an unread count in the page title.
- **Tap a message** (or long-press / right-click) for **Reply**, **Copy**, **Save/Share** and **Delete**. Replies show the quoted message; tap the quote to jump to the original. (The old hover-only delete button couldn't work on a touchscreen.)
- **Emoji picker** and a **full-screen image viewer** with save/share.
- **Call controls** in video calls: mute, camera on/off, switch front/back camera, hang up. The screen stays awake during a call.
- **Connection banner** and automatic catch-up of missed messages and read receipts after you reconnect or return to the app.
- **Android app**: hardware Back button, message and call notifications, save/share files, and an in-app **Server settings** screen. See `ANDROID.md`.

## Video calls from a chat

Open any conversation (1:1 or group) and tap the **camcorder** button in the thread header. This posts an end-to-end encrypted "Video call" invite into the chat and rings everyone who is online right now (accept/decline screen). The call itself runs in a Quick Room — the same peer-to-peer, end-to-end encrypted mesh — and **Leave** takes you back to Messages. Only the room code and caller name pass through the server to make the phone ring; no call content ever does. Note that Quick Rooms hold up to 6 people, so a larger group can only have the first 6 join.

The **door** icon always means Quick Room; the **camcorder** always means a live video call.

## Using Messages

- Search a username in the box at the top — click a result to start (or resume) a conversation with them.
- **Groups**: tap the 👥+ button next to search, name the group, add members by username, create. Every message in a group is encrypted separately to each member's public key (including your own copy) — see "How groups stay end-to-end encrypted" below.
- Existing conversations (both 1:1 and group) appear in the list below, most recent first.
- A green dot on someone's avatar means they're currently online. This is presence metadata only (who's connected right now) — never anything about message content.
- Start typing in a thread and the other person sees "Typing…" (or "@username is typing…" in a group) live. This is purely ephemeral — relayed through the server in real time, never stored anywhere.
- Sent messages show a single ✓; once the recipient has actually opened the thread and seen it, it becomes a double ✓✓. In a group, it turns blue once *everyone* has seen it. The server only ever sees "user X marked message Y as read" — a timestamp and two usernames, never the message content itself.
- In a thread: 😀 for emoji, 📎 to send any file (documents, photos, whatever), 🎤 to record and send a voice message, and 📹 to share a **live Quick Room** right from the conversation — see below.
- Hover a message bubble and click the trash icon for delete options (for me / for everyone).

### Sharing a Quick Room without leaving the app
Tap 📹 in a Messages thread: it generates a room code, sends it as a message in that conversation (a proper encrypted message, decoded into a "Join Quick Room" button on the other end — not a plaintext code sitting in chat history), and opens the room for you in a new tab. Whoever you sent it to just taps the button in their chat to join the same room instantly — no copy-pasting a code through some other app.

### How groups stay end-to-end encrypted
The same message is encrypted once per member — with that member's own public key — before it ever leaves your browser. The server stores and forwards N independent ciphertexts, one per member, and cannot decrypt any of them (this was validated directly: a member's copy is cryptographically useless to any other member, even though they're "in the same conversation"). The trade-off, worth knowing: adding someone to a group later doesn't retroactively give them the old messages — they were never encrypted for that person's key, so there's nothing to decrypt. That's the correct, secure behavior (it's how real E2EE group chats work too), not a bug.

## Using Quick Rooms

Click **"💬 Go to Messages"** to switch, or **"📹 Quick Room"** from within Messages to switch back. One person clicks "Start a new room", shares the 6-character room code some other way (or shares it as an in-app invite from Messages — see above), and up to 5 more people can join with it (6 total). Whoever's already in the room gets notified as each new person connects; a short verification code is shown for each individual connection so you can confirm out loud that nobody's intercepting that specific pairing.

## Turning this into an installable app

*(Unchanged from before — see the PWA and Android/Capacitor sections that were already set up. Quick recap:)*

- **PWA**: deploy over HTTPS, open on mobile, "Add to Home Screen" — works immediately, no build step.
- **Android APK**: see **[ANDROID.md](./ANDROID.md)** for a full, free, step-by-step walkthrough (Android Studio install → pointing the app at your backend → building → optionally signing → optionally publishing). The `android/` folder is already a ready-to-open Capacitor project with a custom icon, camera/mic permissions, and CORS pre-configured.

## Project structure

```
server.js                Express + Socket.IO: mounts all routes, gates sockets by session token,
                          joins each authenticated socket to a room named after their username
                          (for real-time message delivery)
config/db.js              MongoDB connection
models/User.js            username, phoneNumber, passwordHash, publicKey, encryptedPrivateKey
models/Message.js         Per-recipient encrypted messages (one ciphertext copy per person who
                          can read it — 2 for a 1:1 message, N for a group), TTL auto-expiry
models/Group.js            Group name + member usernames (no keys stored here)
routes/auth.js             POST /register, POST /login, GET /me (password hashing, rate-limited)
routes/users.js             GET /search?q=, GET /:username — find people by username
routes/groups.js            POST /, GET /, GET /:id — create/list groups, fetch members' public keys
routes/messages.js          POST /send, GET /inbox, DELETE /:id — all ciphertext in/out
utils/token.js              JWT sign/verify for session tokens
middleware/authMiddleware.js  Express middleware protecting the above routes
public/
  login.html, login.js       Register/login — generates & password-wraps identity keys client-side
  messages.html/.js/.css     The WhatsApp-style messaging UI
  index.html, app.js         Quick Rooms UI - now a WebRTC mesh (multiple PeerLinks) instead of 1:1
  crypto.js                  All encryption: both the Quick Rooms scheme AND the
                              password-wrapping / ECIES scheme used by Messages
  webrtc.js                  One PeerLink = one direct pairwise WebRTC connection (Quick Rooms only)
  config.js                  SERVER_URL — see the Android section for why this matters
```

## Limitations / things to know

- This is a solid, real implementation of both encryption schemes described above — but neither has been through a professional security audit. For anything genuinely high-stakes, use an audited tool (Signal) instead of a custom one.
- **No password reset**, by design — see above. Make sure users understand this.
- **Phone numbers are India-only (`+91`)** for now — both the UI and the server-side regex assume a 10-digit Indian mobile number. Supporting other countries means adding a country selector and a per-country validation pattern (or a proper phone-parsing library) instead of the hardcoded `+91` prefix and regex in `routes/auth.js`.
- **Quick Rooms are capped at `ROOM_MAX_SIZE` (default 6)** — the mesh topology means each person maintains a direct connection to every other person, so both bandwidth and CPU cost per participant grow with room size. Fine for a small group call, not designed to scale past that without switching to a media server (SFU) architecture, which is a materially bigger undertaking.
- **Groups don't retroactively share history with new members** — by design, see above. There's also no way yet to add/remove members after a group is created (would need a small UI + endpoint addition — the model already supports it).
- **Attachments are capped around 6MB raw** (server rejects larger ciphertext) — comfortably covers photos, voice notes, and most documents, but not large videos. Sending a file this way also means it's stored (encrypted) in MongoDB alongside the message like everything else, subject to the same retention window.
- **No forward secrecy between messages** — each message uses a fresh ephemeral keypair (so a single message's key compromise doesn't expose others), but there's no Double-Ratchet-style continuous re-keying like Signal. Reasonable for a project like this; worth knowing if you're evaluating it against Signal specifically.
- The decrypted private key lives in `sessionStorage` for the browser tab's lifetime (cleared on tab close) rather than being re-requested every single action — a deliberate, common trade-off between security and usability. It is never written to `localStorage` or anywhere persistent in unencrypted form.
- Quick Rooms' large file/video transfer speed still depends on both people's upload bandwidth (true P2P, no server relay for that feature).
- **Presence broadcasts to every connected user, not just people you actually talk to** — the simplest correct implementation for this project's scale, but it does mean anyone logged in can in principle see who else is online, similar to how many chat apps' "last seen" works by default. If that matters for your use case, it's a reasonable place to add a "only notify people I actually have a thread with" restriction later.

## What I tested

Since I can't run a real MongoDB or a real browser in the sandbox this was built in, here's exactly what was and wasn't verified directly:

- **Verified**: the full password-wrap + ECIES scheme end-to-end in Node's WebCrypto implementation (register → offline-encrypt → login-and-decrypt → matches original; wrong password correctly fails to recover the key; an attacker without the private key correctly fails to decrypt) — this is the part where a subtle bug would be most costly, so it got the most scrutiny. Also verified the **group** version of this scheme separately: one message encrypted independently to 4 simulated members, each decrypts their own copy correctly, and a member's copy is cryptographically useless to any other member.
- **Verified**: bcrypt password hashing round-trips correctly; all backend routes (auth, users, groups, messages) reject malformed/missing input with proper 400s *before* touching the database; every protected route correctly returns 401 without a valid token; the server starts and every static asset serves correctly; the server fails over gracefully (clear error, no crash) when MongoDB is unreachable — including for group creation and message sending specifically; Socket.IO's auth gate accepts valid tokens and rejects missing/garbage ones; all frontend JS modules pass a syntax check.
- **Verified**: the phone number regex against 7 cases including the exact invalid input that was originally reported (`2233445566` with no country code) — confirmed rejected, both in isolation and live against the running server; a properly-formatted `+91` number confirmed to pass validation.
- **Verified**: the multi-person Quick Room mesh protocol with a real 3-socket test — each newcomer correctly receives the full list of existing participants, existing participants are correctly notified of newcomers, and a signal sent to one specific peer is confirmed to reach only that peer (not broadcast to the room). Also verified room capacity: a 7th join attempt is correctly rejected when the cap is 6.
- **Verified**: presence and typing indicators with a real 2-socket test — a second user connecting correctly triggers a "come online" event for the first user, a typing event sent to a specific username is correctly delivered only to them, and disconnecting correctly triggers a "went offline" event. Also confirmed the `mark-read` endpoint requires auth and short-circuits cleanly on an empty request.
- **Not verified** (no real MongoDB available in this sandbox): the actual register → login → send-message/group-message → receive flow against a live database, and the visual appearance of the new theme/UI and the read-receipt tick marks in an actual browser. Do that first thing after `npm install` on your machine, with `mongod` running, before relying on it.
