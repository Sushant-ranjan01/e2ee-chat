# Security & privacy notes

What the app protects, how, and the honest limits.

## 1. App lock (Android + web)
- **Settings & privacy -> App lock**: 4-8 digit PIN, optional fingerprint, auto-lock after 15 s / 1 / 5 / 15 min.
- The PIN is stored only as a PBKDF2 hash (200,000 rounds). Wrong PINs: 30 s wait after 3, 5 min after 5, 30 min after 8, and after **10** the app signs out and wipes the local message vault and keys.
- **Block screenshots & hide app preview** (Android): `FLAG_SECURE`, on by default; turn it off in Settings. Native code: `android/.../AppSecurityPlugin.java`.
- Limit: this is a screen lock. It does not add disk encryption; keep the phone's own screen lock on.

## 2. Forward secrecy
- Senders encrypt each message to a **one-time key** of the recipient (handed out once by `/api/keys/claim`). The recipient's device deletes that private key right after saving the message to its local vault. When the one-time pool is empty, a **rotating key** (changed daily, old ones deleted after 2 days) is used.
- So a later leak of your password or of the server database cannot decrypt messages you've already read. (Quick Rooms already used per-session keys.)
- The local vault (IndexedDB) is AES-GCM encrypted with a key derived from your identity key, so it opens only after you enter your password. Private one-time keys are non-extractable.
- **Trade-offs to know:**
  - The server only keeps messages until delivered (max 14 days), so history lives on the device. A **new device starts with no history**.
  - One active device at a time: the device you opened most recently receives new messages; another device shows "can't be opened on this device" for those.
  - This is key rotation + deletion (like Signal's prekeys), not a per-message Double Ratchet.
  - It does not stop a malicious server from swapping someone's public key. Fingerprint/safety-number verification for 1:1 chats is the next step for that.

## 3. Server hardening
- Security headers via `helmet`, a strict Content-Security-Policy (no inline scripts), HSTS, camera/mic-only Permissions-Policy, no API caching.
- HTTPS redirect in production, CORS allow-list (`ALLOWED_ORIGIN`), rate limits behind a proxy (`TRUST_PROXY`), 200 KB JSON limit (12 MB only for encrypted messages).
- Login lockout per account (hashed keys, no IPs/usernames stored): 5 wrong tries from one network -> 15 min (doubling), 30 from anywhere -> 1 h. Timing-equalised "no such user". Production refuses to start without a strong `JWT_SECRET`. Sessions default to 14 days.
- The CSP applies to the website served by this server. The APK loads its files locally, so it isn't covered by that header.

## 4. Metadata minimisation
- Messages are erased from the server after `MESSAGE_RETENTION_DAYS` (default **14**).
- **Phone numbers are never stored in readable form**: only a scrypt fingerprint with a secret `PHONE_PEPPER`. Existing numbers are converted automatically at startup. They are no longer in login tokens or API responses.
- No IP addresses, usernames or room codes in server logs; "last login" is no longer recorded; failed-login records are keyed hashes that expire in a day.
- Still visible to the server (inherent to this design): who messages whom and when, and the ciphertext size. Hosting providers also see connection IPs.
