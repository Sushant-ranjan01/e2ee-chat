/**
 * presence.js — which users currently have the app OPEN IN THE FOREGROUND.
 *
 * Used to decide whether to send a push notification: if someone is looking
 * at the app right now, the live socket already delivers the message and a
 * push would just be a duplicate. If they're backgrounded / the app is
 * closed / the phone froze the connection, we push instead.
 *
 * Pure routing metadata (username + socket id + a boolean). No content.
 */
const foreground = new Map(); // username -> Set<socketId>

function setForeground(username, socketId, active) {
  let set = foreground.get(username);
  if (active) {
    if (!set) foreground.set(username, (set = new Set()));
    set.add(socketId);
  } else if (set) {
    set.delete(socketId);
    if (set.size === 0) foreground.delete(username);
  }
}

function removeSocket(username, socketId) {
  setForeground(username, socketId, false);
}

function isForeground(username) {
  return (foreground.get(username)?.size || 0) > 0;
}

module.exports = { setForeground, removeSocket, isForeground };
