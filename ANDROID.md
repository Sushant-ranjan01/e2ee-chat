# Turning this into an Android app — step by step (100% free)

This project already includes a ready-to-open native Android project (the `android/` folder), built with [Capacitor](https://capacitorjs.com/), which wraps the exact same web app you've been running into a real installable `.apk`. Every tool used below is free — no paid accounts, no paid services, nothing. The only optional cost anywhere in this whole process is a **one-time $25** if you later choose to publish on the Google Play Store, and that step is entirely optional (see the very end).

---

## What you'll need (all free)

| Tool | Cost | Why |
|---|---|---|
| [Android Studio](https://developer.android.com/studio) | Free | The official Android development app — includes the Android SDK, an emulator, and everything else needed to build |
| A Google account | Free | Only needed if you use an emulator signed into Play Store services, or if you later publish to Play Store (optional) |
| A Windows/Mac/Linux computer | — | Android Studio runs on all three |
| An Android phone (optional) | — | For testing on a real device instead of/alongside the emulator |
| A USB cable (optional) | — | Only if testing on a real device via USB |

You do **not** need: a paid Apple/Google developer account (unless publishing to Play Store — optional), a Mac (Android doesn't require one, unlike iOS), or any paid CI/build service.

---

## Step 1 — Install Android Studio

1. Go to <https://developer.android.com/studio> and download the installer for your operating system.
2. Run the installer and choose the **Standard** installation when asked — this automatically downloads and sets up the Android SDK, Android Virtual Device (emulator) support, and everything else you need. This step downloads a few GB, so it can take a while depending on your connection.
3. Open Android Studio once when it's done, just to let it finish its first-time setup (it may download a couple more small components).

That's it — this is the only "install something" step. Everything else happens inside Android Studio or from a terminal.

---

## Step 2 — Point the app at your deployed backend

This is the step people most often skip and then wonder why the app doesn't work.

The web version of this app (when you open it at `http://localhost:3000` in a browser) and the backend server live at the same address, so requests like `fetch("/api/auth/login")` just work — "wherever this page came from" already is the server.

**The Android app is different.** Once built, the frontend files are bundled *inside* the app itself — there's no "current page address" to fall back on. You have to tell it explicitly where your backend lives.

1. First, deploy your backend (`server.js` + everything in this project except `public/` and `android/`) somewhere reachable over the internet, with **HTTPS** (required — Android's WebView, like any browser, blocks camera/microphone access and some crypto features on plain HTTP). Good free-tier options for a student project:
   - [Render](https://render.com) — free web service tier, HTTPS included automatically
   - [Railway](https://railway.app) — has a free starter tier
   - Any VPS you already have, behind a free [Let's Encrypt](https://letsencrypt.org/) certificate

   You'll also need a free MongoDB database for it to connect to — [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) has a free forever tier (M0) that's plenty for this project.

2. Once deployed, you'll have a URL like `https://your-app-name.onrender.com`. Open `public/config.js` in this project and change:

   ```js
   export const SERVER_URL = "";
   ```
   to:
   ```js
   export const SERVER_URL = "https://your-app-name.onrender.com";
   ```

3. Also update your deployed backend's `ALLOWED_ORIGIN` environment variable if you've locked it down (see the main README) — it needs to allow requests from the app.

---

## Step 3 — Sync the web app into the Android project

Back in a terminal, from the project's root folder:

```bash
npm install
npm run android:sync
```

This copies everything in `public/` (including your `config.js` change) into `android/app/src/main/assets/public/`, where the Android app actually reads it from. **Run this again any time you change anything in `public/`** — the Android project doesn't auto-update from your source files.

---

## Step 4 — Open the project in Android Studio

Either:
```bash
npm run android:open
```
or manually: open Android Studio → **File → Open** → select the `android` folder inside this project.

The first time you open it, Android Studio will run a **Gradle sync** — this downloads the Android Gradle Plugin and other build tools it needs. This can take several minutes on the first run (it's all free, just slow the first time). You'll see a progress bar at the bottom of the window. Wait for it to finish before doing anything else.

If it shows any red error banners about missing SDK components, click the **"Install missing SDK package(s)"** link it offers — this is still all free, it's just Android Studio fetching pieces of the SDK it needs.

---

## Step 5 — Run it (fastest way to see it working)

With the project open and Gradle sync finished:

1. At the top of the window, you'll see a device dropdown (it might say "No devices"). Click it → **"Create Virtual Device"** if you don't have a real phone connected, pick something like a Pixel 6, pick a system image (any recent Android version), and let it download (free) and create the emulator.
2. Alternatively, connect a real Android phone via USB with **Developer Options → USB Debugging** turned on (Settings → About Phone → tap "Build Number" 7 times to unlock Developer Options, then enable USB Debugging inside it). Your phone will show up in that same dropdown.
3. Click the green ▶ **Run** button. Android Studio builds the app and installs it on whichever device you picked, automatically.

This gives you a real, working install of the app — this is genuinely enough for testing, demoing to a professor, or day-to-day personal use. You don't need to go further unless you specifically want a standalone `.apk` file to share with someone, or to publish it.

---

## Step 6 — Build a standalone `.apk` file (to share it directly)

If you want an actual `.apk` file you can send to someone or install without Android Studio:

1. In Android Studio's menu: **Build → Build App Bundle(s) / APK(s) → Build APK(s)**.
2. Wait for it to finish (a notification appears bottom-right when done, with a "locate" link).
3. The file will be at `android/app/build/outputs/apk/debug/app-debug.apk`.

This is a **debug** build — perfectly installable on any Android phone, just not optimized/minified and not meant for a public app store listing. To install it on a phone:
- Copy the `.apk` to the phone (via USB, email attachment, Google Drive, whatever) and open it from a file manager — Android will ask permission to "install from unknown sources" the first time, which you allow.
- Or, with the phone connected via USB debugging, run `adb install android/app/build/outputs/apk/debug/app-debug.apk` from a terminal.

All free, no signing or accounts required for this.

---

## Step 7 (optional) — A signed release build

A "release" build is smaller/faster and is what you'd need if distributing more broadly or publishing to Play Store. This needs a **signing key** — but generating one is completely free and built into Android Studio, no external service involved:

1. **Build → Generate Signed Bundle / APK**.
2. Choose **APK**, click Next.
3. Click **Create new...** under "Key store path" — this opens a form to generate a new keystore file. Fill in:
   - A save location and password for the keystore file (remember these — you'll need them for any future updates to this same app)
   - An alias, password, and your name/organization details for the key itself (these can be anything; they don't need to be "real" for a personal/student project)
4. Click OK, then Next, choose **release** as the build variant, and finish.

Android Studio generates the keystore file (keep it safe and back it up — if you lose it, you can never update this exact app again, you'd have to publish it as a new app) and produces a signed `.apk` (or `.aab` if you chose App Bundle) under `android/app/release/`. Still entirely free.

---

## Step 8 (fully optional, and the only step that can cost money) — Publishing to Google Play Store

You do not need to do this. Sideloading the APK (Step 6/7) is a completely valid way to use and share this app for free, forever.

If you *do* want it listed on the Play Store for others to find and install normally:

- Google charges a **one-time $25 USD** registration fee for a Play Console developer account (not a subscription — pay once, keep the account forever).
- After that, publishing itself, updates, and Play Console usage are free.
- You'd upload the signed `.aab` from Step 7 through the [Play Console](https://play.google.com/console), fill in a store listing (description, screenshots, privacy policy — you'll need one given this app handles accounts and messages; even a simple one hosted as a GitHub Pages page is fine and free), and submit for review.

This is the only point in this entire guide where money is involved, and it's optional.

---

## Troubleshooting

- **"Gradle sync failed" / can't download dependencies**: Android Studio needs internet access to `dl.google.com`, `repo.maven.apache.org`, and similar during the first sync. If you're behind a restrictive network (college Wi-Fi, corporate proxy), try a different network for this one-time setup step.
- **App installs but can't reach the server / login does nothing**: almost always means `SERVER_URL` in `public/config.js` wasn't set, or was set but you forgot to run `npm run android:sync` afterward. Redo Step 2 and 3.
- **Camera/microphone don't work for voice messages or calls**: make sure your deployed backend is actually on HTTPS, not HTTP — this is required for `getUserMedia` to work at all, in the Android WebView same as in a regular browser.
- **"App not installed" error when sideloading the APK**: usually means you have an older version of the same app already installed with a different signature (e.g. you built once with a debug key and once with a release key) — uninstall the old one first.
