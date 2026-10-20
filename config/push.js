/**
 * push.js — Firebase Cloud Messaging (FCM) sender.
 *
 * This is what makes notifications arrive in REAL TIME even when the Android
 * app is closed or frozen in the background. The server wakes the phone
 * through Google's FCM; Android then shows the notification itself.
 *
 * END-TO-END ENCRYPTION IS UNCHANGED: the server cannot read messages, so the
 * push only says WHO wrote ("New message") - never the text.
 *
 * Setup (once): see ANDROID.md → "Push notifications". You need a Firebase
 * service-account key in the FIREBASE_SERVICE_ACCOUNT env var. If it isn't
 * set, push is simply disabled and everything else keeps working.
 */
const PushToken = require("../models/PushToken");

let messaging = null;
let initTried = false;

function init() {
  if (initTried) return messaging;
  initTried = true;
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!raw) {
    console.log("Push notifications: disabled (FIREBASE_SERVICE_ACCOUNT not set).");
    return null;
  }
  try {
    // Accept either the raw JSON or the JSON base64-encoded (easier for hosts
    // that mangle multi-line env vars).
    const json = raw.trim().startsWith("{") ? raw : Buffer.from(raw, "base64").toString("utf8");
    const admin = require("firebase-admin");
    admin.initializeApp({ credential: admin.credential.cert(JSON.parse(json)) });
    messaging = admin.messaging();
    console.log("Push notifications: enabled (FCM).");
  } catch (err) {
    console.error("Push notifications: could not start FCM -", err.message);
  }
  return messaging;
}

/**
 * Send a push to every phone registered for `username`.
 * opts: { title, body, data (string values only), channel, tag, ttlSeconds }
 * Never throws - a failed push must never break message delivery.
 */
async function sendPushToUser(username, opts) {
  try {
    const m = init();
    if (!m) return;
    const rows = await PushToken.find({ username }).select("token").lean();
    if (rows.length === 0) return;

    const data = {};
    for (const [k, v] of Object.entries(opts.data || {})) {
      if (v !== undefined && v !== null) data[k] = String(v);
    }

    const androidNotification = {
      channelId: opts.channel || "messages",
      icon: "ic_stat_chat",
      color: "#5682B1",
      defaultSound: true,
      defaultVibrateTimings: true,
    };
    // Same tag = a newer alert replaces the older one (e.g. several messages from one chat).
    if (opts.tag) androidNotification.tag = opts.tag;

    const res = await m.sendEachForMulticast({
      tokens: rows.map((r) => r.token),
      notification: { title: opts.title, body: opts.body },
      data,
      android: { priority: "high", ttl: (opts.ttlSeconds || 60 * 60) * 1000, notification: androidNotification },
    });

    // Clean out tokens Google says are dead (app uninstalled, token rotated).
    const dead = [];
    res.responses.forEach((r, i) => {
      const code = r.error?.code || "";
      if (!r.success && /registration-token-not-registered|invalid-registration-token/.test(code)) {
        dead.push(rows[i].token);
      }
    });
    if (dead.length) await PushToken.deleteMany({ token: { $in: dead } });
  } catch (err) {
    console.error("Push send failed:", err.message);
  }
}

module.exports = { sendPushToUser, init };
