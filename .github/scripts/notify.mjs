// SkyMonitor — GitHub Actions notification runner
// Reads subscribers from Cloudflare D1 via REST API, sends Web Push notifications.
// Runs every 5 minutes via .github/workflows/weather-notifications.yml
//
// Required GitHub Actions secrets:
//   CF_API_TOKEN       — Cloudflare API token with D1:Edit permission
//   CF_ACCOUNT_ID      — Cloudflare account ID (dash.cloudflare.com → right sidebar)
//   CF_D1_DATABASE_ID  — D1 database ID (Workers & Pages → D1 → your DB → copy ID)
//   VAPID_PUBLIC_KEY
//   VAPID_PRIVATE_KEY
//   VAPID_EMAIL        — e.g. mailto:you@example.com
//   PIRATE_WEATHER_KEY — PirateWeather API key (for rain alerts)

import { webcrypto } from "crypto";
const { subtle } = webcrypto;

const CF_API_TOKEN      = process.env.CF_API_TOKEN;
const CF_ACCOUNT_ID     = process.env.CF_ACCOUNT_ID;
const CF_D1_DATABASE_ID = process.env.CF_D1_DATABASE_ID;
const VAPID_PUB         = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIV        = process.env.VAPID_PRIVATE_KEY;
const VAPID_EMAIL       = process.env.VAPID_EMAIL || "mailto:admin@skymonitor.app";
const PIRATE_WEATHER    = process.env.PIRATE_WEATHER_KEY;

for (const [k, v] of Object.entries({ CF_API_TOKEN, CF_ACCOUNT_ID, CF_D1_DATABASE_ID, VAPID_PUBLIC_KEY: VAPID_PUB, VAPID_PRIVATE_KEY: VAPID_PRIV })) {
  if (!v) { console.error(`[SkyMonitor] Missing required secret: ${k}`); process.exit(1); }
}

// ── Cloudflare D1 REST API ────────────────────────────────────
// Uses the same ?-style positional parameters as D1 in Workers.

const D1_URL = `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/d1/database/${CF_D1_DATABASE_ID}/query`;

async function d1Query(sql, params = []) {
  const res = await fetch(D1_URL, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${CF_API_TOKEN}`,
      "Content-Type":  "application/json",
    },
    body: JSON.stringify({ sql, params }),
  });
  const data = await res.json();
  if (!data.success) {
    throw new Error("D1 query failed: " + JSON.stringify(data.errors));
  }
  return data.result[0]; // { results: [...], success: true, meta: { changes, ... } }
}

// ── Web Push crypto helpers (RFC 8291 / aes128gcm) ─────────────
// Node.js port of the original Cloudflare Worker crypto.

function b64UrlToBytes(s) {
  const clean   = (s || "").trim().replace(/\s+/g, "");
  const padding = "=".repeat((4 - (clean.length % 4)) % 4);
  const b64     = (clean + padding).replace(/-/g, "+").replace(/_/g, "/");
  // new Uint8Array(...) copies bytes into its own ArrayBuffer so .buffer is pool-safe in Node.js
  return new Uint8Array(Buffer.from(b64, "base64"));
}

function bytesToB64Url(bytes) {
  return Buffer.from(bytes).toString("base64")
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

// Return a correctly-sliced ArrayBuffer from any Buffer/Uint8Array (Node.js pool-safe)
function toAB(buf) {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

async function hkdf(salt, ikm, info, length) {
  const key  = await subtle.importKey("raw", toAB(ikm), "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: toAB(salt), info: toAB(info) }, key, length * 8
  );
  return Buffer.from(bits);
}

async function importVapidKeys(publicKeyB64, privateKeyB64) {
  const pubBytes = b64UrlToBytes(publicKeyB64);
  // Normalise to strict base64url (no padding, - and _ not + and /)
  const dNorm = (privateKeyB64 || "").trim().replace(/\s+/g, "").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  console.log(`[SkyMonitor] VAPID private key length after normalise: ${dNorm.length} chars (expect 43)`);
  // Derive x/y directly from the public key bytes (uncompressed point: 0x04 || x || y)
  const x = bytesToB64Url(pubBytes.slice(1, 33));
  const y = bytesToB64Url(pubBytes.slice(33, 65));
  // Use JWK import — identical to the Cloudflare Worker approach.
  // Node.js validates d ↔ (x,y) during import; if they mismatch it throws DataError.
  const privateKey = await subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", d: dNorm, x, y },
    { name: "ECDSA", namedCurve: "P-256" },
    false, ["sign"]
  );
  return { privateKey, publicKeyBytes: pubBytes };
}

async function buildPushRequest(subscription, payload, vapid, contactEmail) {
  const enc        = new TextEncoder();
  const uaPublic   = b64UrlToBytes(subscription.keys.p256dh);
  const authSecret = b64UrlToBytes(subscription.keys.auth);
  const salt       = Buffer.from(webcrypto.getRandomValues(new Uint8Array(16)));

  const ephemKP  = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = Buffer.from(await subtle.exportKey("raw", ephemKP.publicKey));

  const uaKey      = await subtle.importKey("raw", toAB(uaPublic), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdhShared = Buffer.from(await subtle.deriveBits({ name: "ECDH", public: uaKey }, ephemKP.privateKey, 256));

  const keyInfo = Buffer.concat([Buffer.from(enc.encode("WebPush: info\x00")), uaPublic, asPublic]);
  const ikm     = await hkdf(authSecret, ecdhShared, new Uint8Array(keyInfo), 32);
  const cek     = await hkdf(salt, ikm, new Uint8Array(enc.encode("Content-Encoding: aes128gcm\x00")), 16);
  const nonce   = await hkdf(salt, ikm, new Uint8Array(enc.encode("Content-Encoding: nonce\x00")), 12);

  const cekKey    = await subtle.importKey("raw", toAB(cek), "AES-GCM", false, ["encrypt"]);
  const plaintext = new Uint8Array([...enc.encode(payload), 0x02]);
  const encrypted = Buffer.from(await subtle.encrypt(
    { name: "AES-GCM", iv: toAB(nonce), tagLength: 128 }, cekKey, toAB(plaintext)
  ));

  const record = Buffer.alloc(16 + 4 + 1 + 65 + encrypted.length);
  salt.copy(record, 0);
  record.writeUInt32BE(4096, 16);
  record[20] = 65;
  asPublic.copy(record, 21);
  encrypted.copy(record, 86);

  const audience = new URL(subscription.endpoint).origin;
  const exp      = Math.floor(Date.now() / 1000) + 86400;
  const jwtHead  = bytesToB64Url(Buffer.from(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" }))));
  const jwtBody  = bytesToB64Url(Buffer.from(enc.encode(JSON.stringify({ aud: audience, exp, sub: contactEmail }))));
  const sig      = Buffer.from(await subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, vapid.privateKey,
    new Uint8Array(enc.encode(`${jwtHead}.${jwtBody}`))
  ));
  const jwt      = `${jwtHead}.${jwtBody}.${bytesToB64Url(sig)}`;
  const vapidPub = bytesToB64Url(vapid.publicKeyBytes);

  console.log(`[SkyMonitor] push aud="${audience}" k="${vapidPub.slice(0,20)}..."`);

  return {
    url:  subscription.endpoint,
    init: {
      method:  "POST",
      headers: {
        "Content-Type":     "application/octet-stream",
        "Content-Encoding": "aes128gcm",
        "Authorization":    `vapid t=${jwt},k=${vapidPub}`,
        "TTL":              "86400",
        "Urgency":          "high",
      },
      body:   record,
      signal: AbortSignal.timeout(20000),
    },
  };
}

// ── Dead-subscription detector ────────────────────────────────
// Returns true when a push response means the subscription can never
// be used again with the current VAPID key and should be deleted.
//   410 / 404 — browser unsubscribed or endpoint gone
//   403 BadJwtToken / ExpiredJwtToken — Apple (and some others) reject
//     when the VAPID key in k= doesn't match the key used at subscribe-time.
//     Re-subscribing the user with the current VAPID key is the only fix.

function isDeadSubscription(status, bodyText) {
  if (status === 410 || status === 404) return true;
  if (status === 403) {
    const lc = (bodyText || "").toLowerCase();
    if (lc.includes("badjwttoken") || lc.includes("expiredjwttoken") || lc.includes("invalidjwt")) return true;
  }
  return false;
}

// ── Notification builders ─────────────────────────────────────

function buildAlertNotification(properties) {
  const event = properties.event || "Weather Alert";
  const e     = event.toLowerCase();
  const searchText = [properties.description || "", properties.headline || "", event].join(" ").toLowerCase();

  if (e.includes("tornado") && searchText.includes("tornado emergency"))
    return { title: "🌪️ TORNADO EMERGENCY 🌪️", body: "A TORNADO EMERGENCY HAS BEEN ISSUED FOR YOUR AREA! THIS IS AN EXTREMELY DANGEROUS SITUATION! TAKE COVER NOW!" };
  if (e.includes("tornado warning") && searchText.includes("particularly dangerous situation"))
    return { title: "🌪️ PDS Tornado Warning", body: "A Tornado Warning has been issued for your area! THIS IS A PARTICULARLY DANGEROUS SITUATION! TAKE COVER NOW!" };
  if (e.includes("tornado warning"))
    return { title: "🌪️ Tornado Warning", body: "A Tornado Warning has been issued for your area! TAKE COVER NOW!" };
  if (e.includes("tornado watch"))
    return { title: "🌪️ Tornado Watch", body: "A Tornado Watch has been issued for your area. Conditions are favorable for tornadoes. Be ready to take cover immediately." };
  if (e.includes("severe thunderstorm warning") && searchText.includes("destructive"))
    return { title: "⛈️ DESTRUCTIVE Severe Thunderstorm Warning", body: "A Severe Thunderstorm Warning has been issued for your area! It is causing DESTRUCTIVE damage! TAKE COVER NOW!" };
  if (e.includes("severe thunderstorm warning"))
    return { title: "⛈️ Severe Thunderstorm Warning", body: "A Severe Thunderstorm Warning has been issued for your area! MOVE TO AN INTERIOR ROOM!" };
  if (e.includes("severe thunderstorm watch"))
    return { title: "⛈️ Severe Thunderstorm Watch", body: "A Severe Thunderstorm Watch has been issued for your area. Severe thunderstorms are possible. Stay alert." };
  if (e.includes("flash flood") && searchText.includes("flash flood emergency"))
    return { title: "🌊 FLASH FLOOD EMERGENCY 🌊", body: "A FLASH FLOOD EMERGENCY HAS BEEN ISSUED FOR YOUR AREA! THIS IS AN EXTREMELY DANGEROUS SITUATION! SEEK HIGHER GROUND NOW!" };
  if (e.includes("flash flood warning"))
    return { title: "🌊 Flash Flood Warning", body: "A Flash Flood Warning has been issued for your area! TURN AROUND, DON'T DROWN!" };
  if (e.includes("flash flood watch"))
    return { title: "🌊 Flash Flood Watch", body: "A Flash Flood Watch has been issued for your area. Flash flooding is possible. Move to higher ground if flooding develops." };
  if (e.includes("flood warning"))
    return { title: "🌊 Flood Warning", body: "A Flood Warning has been issued for your area! Avoid flooded roads and low-lying areas. TURN AROUND, DON'T DROWN!" };
  if (e.includes("flood"))
    return { title: "🌊 " + event, body: `A ${event} has been issued for your area. Avoid flood-prone areas and any flooded roads.` };
  if (e.includes("hurricane warning") || e.includes("tropical storm warning"))
    return { title: "🌀 " + event, body: `A ${event} has been issued for your area! EVACUATE IMMEDIATELY if ordered. Do not wait — conditions will deteriorate rapidly!` };
  if (e.includes("hurricane") || e.includes("tropical"))
    return { title: "🌀 " + event, body: `A ${event} has been issued for your area. Monitor official guidance and be prepared to evacuate if ordered.` };
  if (e.includes("blizzard warning"))
    return { title: "❄️ Blizzard Warning", body: "A Blizzard Warning has been issued for your area! AVOID ALL TRAVEL. Dangerous whiteout conditions and life-threatening cold expected." };
  if (e.includes("ice storm warning"))
    return { title: "🧊 Ice Storm Warning", body: "An Ice Storm Warning has been issued for your area! Dangerous ice accumulation expected. Avoid travel." };
  if (e.includes("winter storm warning"))
    return { title: "❄️ Winter Storm Warning", body: "A Winter Storm Warning has been issued for your area. Significant snow and ice are expected. Limit travel." };
  if (e.includes("snow squall warning"))
    return { title: "❄️ Snow Squall Warning", body: "A Snow Squall Warning has been issued for your area. Sudden drops in visibility to near zero are imminent. DO NOT TRAVEL!" };
  if (e.includes("winter storm watch"))
    return { title: "❄️ Winter Storm Watch", body: "A Winter Storm Watch has been issued for your area. Hazardous winter conditions are possible. Make preparations now." };
  if (e.includes("winter") || e.includes("blizzard") || e.includes("snow"))
    return { title: "❄️ " + event, body: `A ${event} has been issued for your area. Prepare for wintry conditions and potential travel impacts.` };
  if (e.includes("red flag warning") || e.includes("fire weather watch"))
    return { title: "🔥 " + event, body: `A ${event} is in effect. Extreme fire danger — hot, dry, and windy conditions. Avoid any activities that could spark a fire.` };
  if (e.includes("fire warning"))
    return { title: "🔥 " + event, body: `A ${event} has been issued for your area. A dangerous wildfire is occurring. Follow local guidance.` };
  if (e.includes("fire"))
    return { title: "🔥 " + event, body: `A ${event} has been issued for your area. Dangerous fire conditions exist. Follow all evacuation orders immediately.` };
  if (e.includes("dust storm warning") || e.includes("dust storm"))
    return { title: "🌫️ Dust Storm Warning", body: "A Dust Storm Warning has been issued for your area! PULL ASIDE, STAY ALIVE! Exit roads if visibility drops." };
  if (e.includes("blowing dust advisory"))
    return { title: "🌫️ Blowing Dust Advisory", body: "A Blowing Dust Advisory has been issued for your area. Reduced visibility possible. Use caution while driving." };
  if (e.includes("extreme heat warning"))
    return { title: "🌡️ Extreme Heat Warning", body: "An Extreme Heat Warning has been issued for your area! Dangerously hot conditions. Stay hydrated, stay indoors, and check on vulnerable neighbors." };
  if (e.includes("heat advisory") || e.includes("heat warning") || e.includes("extreme heat watch"))
    return { title: "🌡️ " + event, body: `A ${event} has been issued for your area. Take precautions in the heat — stay hydrated and limit outdoor activity.` };
  if (e.includes("dense fog advisory"))
    return { title: "🌫️ Dense Fog Advisory", body: "A Dense Fog Advisory has been issued for your area. Near-zero visibility possible. Slow down and use low-beam headlights." };
  if (e.includes("high wind warning"))
    return { title: "💨 High Wind Warning", body: "A High Wind Warning has been issued for your area! Dangerous wind gusts expected. Secure outdoor objects and avoid driving high-profile vehicles." };
  if (e.includes("wind advisory") || e.includes("wind warning") || e.includes("high wind watch"))
    return { title: "💨 " + event, body: `A ${event} has been issued for your area. Strong winds are expected. Secure loose outdoor items.` };
  if (e.includes("tsunami warning"))
    return { title: "🌊 TSUNAMI WARNING 🌊", body: "A TSUNAMI WARNING HAS BEEN ISSUED FOR YOUR AREA! MOVE IMMEDIATELY TO HIGH GROUND OR INLAND!" };
  if (e.includes("tsunami watch") || e.includes("tsunami advisory"))
    return { title: "🌊 " + event, body: `A ${event} is in effect. Be ready to move to high ground immediately if ordered.` };
  return { title: `⚠️ ${event}`, body: `A ${event} has been issued for your area.` };
}

function normalizeSPCLabel(raw) {
  if (!raw) return null;
  const s = String(raw).trim().toUpperCase();
  if (s === "TSTM" || s === "GENERAL THUNDERSTORMS" || s === "1") return null;
  if (s === "MRGL" || s === "2" || s.startsWith("MARG")) return "MRGL";
  if (s === "SLGT" || s === "3" || s.startsWith("SLIGH") || s.startsWith("SLIG")) return "SLGT";
  if (s === "ENH"  || s === "4" || s.startsWith("ENHAN")) return "ENH";
  if (s === "MDT"  || s === "5" || s.startsWith("MOD"))   return "MDT";
  if (s === "HIGH" || s === "6" || s.startsWith("HIGH"))  return "HIGH";
  return null;
}

function normalizeWPCLabel(raw) {
  if (!raw) return null;
  const s = String(raw).trim().toUpperCase();
  if (s === "0" || s === "NONE") return null;
  if (s === "MRGL" || s.startsWith("MARG"))                              return "MRGL";
  if (s === "SLGT" || s.startsWith("SLIGH") || s.startsWith("SLI"))     return "SLGT";
  if (s === "MDT"  || s.startsWith("MOD"))                               return "MDT";
  if (s === "HIGH" || s.startsWith("HIGH"))                              return "HIGH";
  return null;
}

function parseSPCStored(val) {
  if (!val) return { label: null, notifiedAt: 0 };
  const s = String(val), colon = s.lastIndexOf(":");
  if (colon < 0) return { label: normalizeSPCLabel(s), notifiedAt: 0 };
  return { label: normalizeSPCLabel(s.slice(0, colon)), notifiedAt: parseInt(s.slice(colon + 1)) || 0 };
}

function parseWPCStored(val) {
  if (!val) return { label: null, notifiedAt: 0 };
  const s = String(val), colon = s.lastIndexOf(":");
  if (colon < 0) return { label: normalizeWPCLabel(s), notifiedAt: 0 };
  return { label: normalizeWPCLabel(s.slice(0, colon)), notifiedAt: parseInt(s.slice(colon + 1)) || 0 };
}

const SPC_RISK_ORDER = ["TSTM", "MRGL", "SLGT", "ENH", "MDT", "HIGH"];
const ERO_RISK_ORDER = ["MRGL", "SLGT", "MDT", "HIGH"];

function buildSPCOutlookNotif(label) {
  switch (label) {
    case "MRGL": return { title: "🟢 SPC Marginal Risk",    body: "A Marginal Risk of severe thunderstorms has been issued for your area. Isolated severe storms are possible, but coverage and intensity are expected to be low. Stay weather-aware." };
    case "SLGT": return { title: "🟡 SPC Slight Risk",      body: "A Slight Risk of severe thunderstorms has been issued for your area. Scattered severe storms are possible, with damaging wind gusts, large hail, and a tornado possible. Monitor conditions throughout the day." };
    case "ENH":  return { title: "🟠 SPC Enhanced Risk",    body: "An Enhanced Risk of severe thunderstorms has been issued for your area. Several severe storms are likely, with damaging winds, large hail, and tornadoes possible. Have a shelter plan ready and know where to go." };
    case "MDT":  return { title: "🔴 SPC Moderate Risk",    body: "A Moderate Risk of severe thunderstorms has been issued for your area. Significant severe weather is expected — strong tornadoes, very large hail, and widespread destructive winds are all likely. Know your shelter NOW and stay alert all day." };
    case "HIGH": return { title: "🟣 SPC HIGH RISK ⚠️",    body: "A HIGH RISK of severe thunderstorms has been issued for your area. This is a RARE, LIFE-THREATENING situation. Violent long-track tornadoes, extremely large hail, and widespread destructive winds are expected. HAVE YOUR SHELTER PLAN READY AND STAY ALERT ALL DAY." };
    default:     return { title: `⛈️ SPC ${label} Risk`,   body: `The SPC has issued a ${label} risk of severe thunderstorms for your area. Monitor conditions closely.` };
  }
}

function buildSPCMDNotif(mdNum) {
  return { title: `⚡ SPC Mesoscale Discussion #${mdNum}`, body: `SPC Mesoscale Discussion #${mdNum} is now active for your area. Forecasters are watching for potential severe weather development — conditions may evolve quickly.` };
}

function buildWPCOutlookNotif(label) {
  switch (label) {
    case "MRGL": return { title: "🟢 WPC Marginal Rainfall Risk", body: "A Marginal Risk for excessive rainfall has been issued for your area. Localized flash flooding is possible, mainly in low-lying areas and near small streams. Monitor any flood advisories that may be issued." };
    case "SLGT": return { title: "🟡 WPC Slight Rainfall Risk",   body: "A Slight Risk for excessive rainfall has been issued for your area. Scattered flash flooding is possible, particularly in flood-prone and low-lying areas. Avoid crossing flooded roads and stay alert." };
    case "MDT":  return { title: "🟠 WPC Moderate Rainfall Risk", body: "A Moderate Risk for excessive rainfall has been issued for your area. Flash flooding is likely in numerous locations. Avoid low-lying areas and flooded roads — turn around, don't drown. Be ready to move to higher ground quickly." };
    case "HIGH": return { title: "🔴 WPC HIGH Rainfall Risk ⚠️", body: "A HIGH RISK for excessive rainfall has been issued for your area. Widespread, life-threatening flash flooding is expected. This is a RARE and EXTREMELY DANGEROUS situation. Move to higher ground NOW and stay off all roads." };
    default:     return { title: `💧 WPC Excessive Rainfall: ${label} Risk`, body: `The WPC has issued a ${label} risk for excessive rainfall in your area. Flash flooding is possible — monitor conditions and any flood alerts closely.` };
  }
}

function buildWPCMPDNotif(mpdNum) {
  return { title: `💧 WPC Precipitation Discussion #${mpdNum}`, body: `WPC Mesoscale Precipitation Discussion #${mpdNum} is now active for your area. Heavy rainfall and potential flooding are being closely monitored by forecasters.` };
}

// ── ArcGIS helper ─────────────────────────────────────────────

async function fetchArcGIS(url) {
  try {
    const res  = await fetch(url, { signal: AbortSignal.timeout(6000) });
    if (!res.ok) return null;
    const data = await res.json();
    if (data?.features?.length > 0) return data.features[0].attributes;
  } catch {}
  return null;
}

// ── Precipitation check ───────────────────────────────────────

async function checkPrecipitation(row, vapid) {
  if (!PIRATE_WEATHER) return;
  if (row.precip_notified_until && new Date(row.precip_notified_until) > new Date()) return;

  let minutely = [], hourly = [], timezone = "UTC";
  try {
    const res = await fetch(
      `https://api.pirateweather.net/forecast/${PIRATE_WEATHER}/${row.lat},${row.lon}?exclude=currently,daily,alerts&units=us`,
      { signal: AbortSignal.timeout(8000) }
    );
    if (!res.ok) return;
    const data = await res.json();
    minutely = data.minutely?.data ?? [];
    hourly   = data.hourly?.data   ?? [];
    timezone = data.timezone       || "UTC";
  } catch { return; }

  if (minutely.length < 2) return;

  const TRIGGER_THRESHOLD = 0.15;
  const THUNDER_THRESHOLD = 0.02;
  const HEAVY_THRESHOLD   = 0.40;
  const END_THRESHOLD     = 0.02;
  const LOOKAHEAD_MINS    = 15;
  const COOLDOWN_HOURS    = 2;

  const isThunderstorm = hourly.slice(0, 3).some(h => (h.icon || "").includes("thunder"));
  const lookahead      = minutely.slice(1, LOOKAHEAD_MINS + 1);
  const threshold      = isThunderstorm ? THUNDER_THRESHOLD : TRIGGER_THRESHOLD;
  const startIndex     = lookahead.findIndex(m => (m.precipIntensity ?? 0) >= threshold);
  if (startIndex === -1) return;

  const fullStartIdx = startIndex + 1;
  const startEntry   = minutely[fullStartIdx];
  const rawType      = startEntry?.precipType || hourly[0]?.precipType || "rain";
  const precipType   = rawType.toLowerCase();

  let fullEndIdx    = fullStartIdx;
  let peakIntensity = startEntry?.precipIntensity ?? 0;
  for (let i = fullStartIdx + 1; i < minutely.length; i++) {
    const intensity = minutely[i]?.precipIntensity ?? 0;
    if (intensity >= END_THRESHOLD) { fullEndIdx = i; if (intensity > peakIntensity) peakIntensity = intensity; }
    else break;
  }

  let durationMins         = fullEndIdx - fullStartIdx + 1;
  const minutelyWindowFull = fullEndIdx >= minutely.length - 2;

  if (minutelyWindowFull && hourly.length > 0) {
    const hrRainStart = hourly.findIndex(h => (h.precipIntensity ?? 0) >= END_THRESHOLD);
    if (hrRainStart !== -1) {
      let lastRainyHr = hrRainStart;
      for (let i = hrRainStart + 1; i < hourly.length; i++) {
        if ((hourly[i].precipIntensity ?? 0) >= END_THRESHOLD) {
          lastRainyHr = i;
          const hi = hourly[i].precipIntensity ?? 0;
          if (hi > peakIntensity) peakIntensity = hi;
        } else break;
      }
      durationMins = 60 + (lastRainyHr - hrRainStart) * 60;
    }
  }

  const startTimestamp = startEntry?.time ?? (Date.now() / 1000 + (startIndex + 1) * 60);
  const startTimeStr   = new Intl.DateTimeFormat("en-US", {
    weekday: "short", month: "short", day: "numeric",
    hour: "numeric", minute: "2-digit", hour12: true,
    timeZone: timezone, timeZoneName: "short",
  }).format(new Date(startTimestamp * 1000));

  let precipWord, showerWord, title, emoji;
  if      (precipType === "snow")  { precipWord = "Snow";  showerWord = "snow shower";       title = "Snow Alert";           emoji = "🌨️"; }
  else if (precipType === "sleet") { precipWord = "Sleet"; showerWord = "wintry mix shower"; title = "Winter Weather Alert"; emoji = "🧊"; }
  else                              { precipWord = "Rain";  showerWord = "rain shower";        title = "Rain Alert";           emoji = "🌧️"; }

  let durationPhrase;
  if      (durationMins < 20)  durationPhrase = null;
  else if (durationMins < 50)  durationPhrase = `lasting about ${Math.round(durationMins / 5) * 5} minutes`;
  else if (durationMins < 90)  durationPhrase = "lasting about an hour";
  else if (durationMins < 240) durationPhrase = "continuing over the next hour or two";
  else                          durationPhrase = "continuing over the next few hours";

  const parts = [];
  if (isThunderstorm) parts.push("Thunderstorms nearby.");
  if (!durationPhrase) parts.push(`A brief ${showerWord} will begin around ${startTimeStr}.`);
  else                 parts.push(`${precipWord} will begin around ${startTimeStr}, ${durationPhrase}.`);
  if (peakIntensity >= HEAVY_THRESHOLD) {
    if      (precipType === "snow")  parts.push("Snow heavy at times, accumulation likely.");
    else if (precipType === "sleet") parts.push("Sleet heavy at times.");
    else                              parts.push("Rain heavy at times.");
  }

  const subscription = JSON.parse(row.subscription);
  const payload = JSON.stringify({
    title: `${emoji} ${title}`, body: parts.join(" "),
    icon: "https://cdn-icons-png.flaticon.com/512/1779/1779927.png",
    badge: "https://cdn-icons-png.flaticon.com/512/1779/1779927.png",
    tag: "precip-alert", url: "/sky-monitor/",
  });

  try {
    const req     = await buildPushRequest(subscription, payload, vapid, VAPID_EMAIL);
    const res     = await fetch(req.url, req.init);
    const rawBody = res.ok ? "" : await res.text().catch(() => "");
    if (rawBody) console.log(`[SkyMonitor] precip push → HTTP ${res.status} — ${rawBody}`);
    if (isDeadSubscription(res.status, rawBody)) {
      if (res.status === 403) console.warn("[SkyMonitor] ⚠️  VAPID key mismatch (Apple) — subscription registered with a different key. Deleting; user must re-subscribe.");
      await d1Query("DELETE FROM push_subscriptions WHERE endpoint = ?", [row.endpoint]);
      return;
    }
    if (res.ok || res.status === 201) {
      const cooldownUntil = new Date(Date.now() + COOLDOWN_HOURS * 60 * 60 * 1000).toISOString();
      await d1Query(
        "UPDATE push_subscriptions SET precip_notified_until = ? WHERE endpoint = ?",
        [cooldownUntil, row.endpoint]
      );
    }
  } catch {}
}

// ── SPC/WPC check ─────────────────────────────────────────────

async function checkSPCAndWPC(row, vapid) {
  const prefs = row.prefs ? JSON.parse(row.prefs) : {};
  if (!prefs.spcOutlookEnabled && !prefs.spcMdEnabled && !prefs.wpcOutlookEnabled && !prefs.wpcMpdEnabled) return;

  const subscription = JSON.parse(row.subscription);
  const geo  = `geometry=${row.lon},${row.lat}&geometryType=esriGeometryPoint&inSR=4326&spatialRel=esriSpatialRelIntersects&outFields=*&returnGeometry=false&f=json`;
  const BASE = "https://mapservices.weather.noaa.gov/vector/rest/services";

  const notifs  = [];
  const updates = {};

  if (prefs.spcOutlookEnabled) {
    const attrs    = await fetchArcGIS(`${BASE}/outlooks/SPC_wx_outlks/MapServer/1/query?${geo}`);
    const current  = normalizeSPCLabel(attrs ? (attrs.LABEL || attrs.label || attrs.dn) : null);
    const stored   = parseSPCStored(row.last_spc_outlook);
    const nowTs    = Math.floor(Date.now() / 1000);
    const hoursSince = (nowTs - stored.notifiedAt) / 3600;
    const currentIdx = current ? SPC_RISK_ORDER.indexOf(current) : -1;
    const lastIdx    = stored.label ? SPC_RISK_ORDER.indexOf(stored.label) : -1;
    const effectiveLastIdx = (stored.notifiedAt > 0 && hoursSince > 20) ? -1 : lastIdx;
    const shouldNotify = current && (currentIdx > effectiveLastIdx || (current === stored.label && hoursSince > 8));

    if (shouldNotify) {
      notifs.push({ ...buildSPCOutlookNotif(current), tag: `spc-outlook-${current}` });
      updates.last_spc_outlook = `${current}:${nowTs}`;
    } else if (current !== null) {
      updates.last_spc_outlook = stored.notifiedAt > 0 ? `${current}:${stored.notifiedAt}` : current;
    }
  }

  if (prefs.spcMdEnabled) {
    const attrs  = await fetchArcGIS(`${BASE}/outlooks/spc_mesoscale_discussion/MapServer/0/query?${geo}`);
    const mdName = attrs ? (attrs.Name || attrs.name || attrs.MD_NUM) : null;
    const mdNum  = mdName ? String(mdName).replace(/[^0-9]/g, "") : null;
    if (mdNum && mdNum !== row.last_spc_md) {
      notifs.push({ ...buildSPCMDNotif(mdNum), tag: `spc-md-${mdNum}`, _updateKey: "last_spc_md", _updateVal: mdNum });
    } else if (mdNum !== null) {
      updates.last_spc_md = mdNum;
    }
  }

  if (prefs.wpcOutlookEnabled) {
    const attrs    = await fetchArcGIS(`${BASE}/hazards/wpc_precip_hazards/MapServer/0/query?${geo}`);
    const eroLabel = normalizeWPCLabel(attrs ? (attrs.outlook || attrs.label || attrs.LABEL || attrs.risk || attrs.RISK || null) : null);
    const stored   = parseWPCStored(row.last_wpc_outlook);
    const nowTs    = Math.floor(Date.now() / 1000);
    const hoursW   = (nowTs - stored.notifiedAt) / 3600;
    const currentIdx = eroLabel ? ERO_RISK_ORDER.indexOf(eroLabel) : -1;
    const lastIdx    = stored.label ? ERO_RISK_ORDER.indexOf(stored.label) : -1;
    const effectiveLastIdx = (stored.notifiedAt > 0 && hoursW > 20) ? -1 : lastIdx;
    const shouldNotify = eroLabel && (currentIdx > effectiveLastIdx || (eroLabel === stored.label && hoursW > 8));

    if (shouldNotify) {
      notifs.push({ ...buildWPCOutlookNotif(eroLabel), tag: `wpc-ero-${eroLabel}` });
      updates.last_wpc_outlook = `${eroLabel}:${nowTs}`;
    } else if (eroLabel !== null) {
      updates.last_wpc_outlook = stored.notifiedAt > 0 ? `${eroLabel}:${stored.notifiedAt}` : eroLabel;
    }
  }

  if (prefs.wpcMpdEnabled) {
    let currentMpdNums = [];
    try {
      const mpdRes = await fetch(
        `https://wpcmetwatch.skymonitor-account.workers.dev/?lat=${row.lat}&lon=${row.lon}`,
        { signal: AbortSignal.timeout(6000) }
      );
      if (mpdRes.ok) {
        const mpdData = await mpdRes.json();
        currentMpdNums = (mpdData.mpds || []).map(m => String(m.id).replace(/[^0-9]/g, "")).filter(Boolean);
      }
    } catch {}

    const lastKnown = row.last_wpc_mpd ? String(row.last_wpc_mpd).split(",").filter(Boolean) : [];
    for (const mpdNum of currentMpdNums) {
      if (!lastKnown.includes(mpdNum))
        notifs.push({ ...buildWPCMPDNotif(mpdNum), tag: `wpc-mpd-${mpdNum}`, _updateKey: "_mpd", _updateVal: mpdNum });
    }
    if (currentMpdNums.length === 0) updates.last_wpc_mpd = null;
    updates._mpdCurrent   = currentMpdNums;
    updates._mpdLastKnown = lastKnown;
  }

  const mpdCurrentNums = updates._mpdCurrent  || [];
  const mpdLastKnown   = updates._mpdLastKnown || [];
  delete updates._mpdCurrent;
  delete updates._mpdLastKnown;

  const confirmedUpdates  = {};
  const successfulMpdNums = new Set();

  for (const notif of notifs) {
    const payload = JSON.stringify({
      title: notif.title, body: notif.body,
      icon: "https://cdn-icons-png.flaticon.com/512/1779/1779927.png",
      badge: "https://cdn-icons-png.flaticon.com/512/1779/1779927.png",
      tag: notif.tag, url: "/sky-monitor/",
    });
    try {
      const req     = await buildPushRequest(subscription, payload, vapid, VAPID_EMAIL);
      const res     = await fetch(req.url, req.init);
      const rawBody = res.ok ? "" : await res.text().catch(() => "");
      if (isDeadSubscription(res.status, rawBody)) {
        if (res.status === 403) console.warn("[SkyMonitor] ⚠️  VAPID key mismatch (Apple) — subscription registered with a different key. Deleting; user must re-subscribe.");
        await d1Query("DELETE FROM push_subscriptions WHERE endpoint = ?", [row.endpoint]);
        return;
      }
      if (res.ok || res.status === 201) {
        if (notif._updateKey === "_mpd") successfulMpdNums.add(notif._updateVal);
        else if (notif._updateKey)       confirmedUpdates[notif._updateKey] = notif._updateVal;
      }
    } catch {}
    await new Promise(r => setTimeout(r, 50));
  }

  if (mpdCurrentNums.length > 0) {
    const newKnown = mpdCurrentNums.filter(id => mpdLastKnown.includes(id) || successfulMpdNums.has(id));
    confirmedUpdates.last_wpc_mpd = newKnown.length > 0 ? newKnown.join(",") : null;
    delete updates.last_wpc_mpd;
  }

  const allUpdates = { ...updates, ...confirmedUpdates };
  const keys = Object.keys(allUpdates);
  if (keys.length > 0) {
    const setClauses = keys.map((k, i) => `${k} = ?${i + 1}`).join(", ");
    const vals       = Object.values(allUpdates);
    await d1Query(
      `UPDATE push_subscriptions SET ${setClauses} WHERE endpoint = ?${vals.length + 1}`,
      [...vals, row.endpoint]
    );
  }
}

// ── Main ──────────────────────────────────────────────────────

console.log(`[SkyMonitor] Starting — ${new Date().toISOString()}`);

const vapid = await importVapidKeys(VAPID_PUB, VAPID_PRIV);

// Verify the private key matches the public key by importing as ECDH (extractable)
// and comparing the derived public point against VAPID_PUBLIC_KEY.
{
  const pubBytes = b64UrlToBytes(VAPID_PUB);
  const dNorm    = VAPID_PRIV.trim().replace(/\s+/g, "").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const x = bytesToB64Url(pubBytes.slice(1, 33));
  const y = bytesToB64Url(pubBytes.slice(33, 65));
  // Import d+x+y as ECDH (extractable) — Node.js validates d↔(x,y) here too
  const ecdhKey  = await subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", d: dNorm, x, y },
    { name: "ECDH", namedCurve: "P-256" }, true, []
  );
  // Export and reconstruct uncompressed public point (0x04 || x || y)
  const jwk        = await subtle.exportKey("jwk", ecdhKey);
  const derivedPub = new Uint8Array([0x04, ...b64UrlToBytes(jwk.x), ...b64UrlToBytes(jwk.y)]);
  const match = derivedPub.length === pubBytes.length && derivedPub.every((b, i) => b === pubBytes[i]);
  console.log(`[SkyMonitor] VAPID key-pair match: ${match ? "✅ YES" : "❌ NO — private key does not match VAPID_PUBLIC_KEY"}`);
  if (!match) {
    console.error("[SkyMonitor] Aborting — fix your VAPID keys before continuing.");
    process.exit(1);
  }
}

const { results: rows } = await d1Query("SELECT * FROM push_subscriptions");
console.log(`[SkyMonitor] ${rows.length} subscriber(s)`);

for (const row of rows) {
  const knownIds = JSON.parse(row.known_alert_ids || "[]");
  const prefs    = row.prefs ? JSON.parse(row.prefs) : {};

  // Diagnostic: show subscription fingerprint so we can verify a re-subscribe landed
  try {
    const sub = JSON.parse(row.subscription);
    const p256 = (sub?.keys?.p256dh || "").slice(-12);
    const auth = (sub?.keys?.auth   || "").slice(-8);
    console.log(`[SkyMonitor] subscriber endpoint=...${row.endpoint.slice(-30)}  p256dh=...${p256}  auth=...${auth}`);
  } catch {}

  // ── NWS alerts ────────────────────────────────────────────
  if (prefs.alertEnabled !== false) {
    let alerts = [];
    try {
      const nwsRes = await fetch(
        `https://api.weather.gov/alerts/active?point=${row.lat},${row.lon}`,
        { headers: { "User-Agent": "SkyMonitor/1.1" }, signal: AbortSignal.timeout(8000) }
      );
      console.log(`[SkyMonitor] NWS API → HTTP ${nwsRes.status} for (${row.lat},${row.lon})`);
      if (nwsRes.ok) {
        alerts = (await nwsRes.json()).features ?? [];
        console.log(`[SkyMonitor] ${alerts.length} active alert(s): ${alerts.map(a => a.properties?.event).join(", ") || "none"}`);
      }
    } catch (err) {
      console.warn(`[SkyMonitor] NWS fetch error: ${err.message}`);
    }

    const currentIds    = alerts.map(a => a.id);
    console.log(`[SkyMonitor] known IDs: ${knownIds.length}, current IDs: ${currentIds.length}`);
    const importantTypes = [
      "tornado warning","tornado watch","severe thunderstorm warning","severe thunderstorm watch",
      "flash flood warning","flash flood emergency","flash flood watch","extreme wind",
      "hurricane warning","storm surge warning","blizzard warning","snow squall warning",
      "ice storm warning","tsunami warning","dust storm warning",
    ];
    const newAlerts = alerts.filter(a => {
      const p = a.properties ?? {}, evt = (p.event || "").toLowerCase();
      return !knownIds.includes(a.id) && p.messageType === "Alert" && p.status === "Actual" && !evt.includes("expir");
    });
    const filteredAlerts = (prefs.alertType === "important")
      ? newAlerts.filter(a => importantTypes.some(t => (a.properties?.event || "").toLowerCase().includes(t)))
      : newAlerts;
    console.log(`[SkyMonitor] new alerts: ${newAlerts.length}, after filter: ${filteredAlerts.length}`);

    let subDeleted = false;
    const sentAlertIds = new Set();

    for (const alert of filteredAlerts) {
      const { title, body } = buildAlertNotification(alert.properties);
      const payload = JSON.stringify({
        title, body,
        icon: "https://cdn-icons-png.flaticon.com/512/1779/1779927.png",
        badge: "https://cdn-icons-png.flaticon.com/512/1779/1779927.png",
        tag: alert.id, url: "/sky-monitor/",
      });
      try {
        const req     = await buildPushRequest(JSON.parse(row.subscription), payload, vapid, VAPID_EMAIL);
        const res     = await fetch(req.url, req.init);
        const rawBody = res.ok ? "" : await res.text().catch(() => "");
        console.log(`[SkyMonitor] alert push "${alert.properties?.event}" → HTTP ${res.status}${rawBody ? ` — ${rawBody}` : ""}`);
        if (isDeadSubscription(res.status, rawBody)) {
          if (res.status === 403) console.warn("[SkyMonitor] ⚠️  VAPID key mismatch (Apple) — subscription registered with a different key. Deleting; user must re-subscribe with the current VAPID key.");
          await d1Query("DELETE FROM push_subscriptions WHERE endpoint = ?", [row.endpoint]);
          subDeleted = true; break;
        }
        if (res.ok || res.status === 201) sentAlertIds.add(alert.id);
      } catch (err) { console.warn("[SkyMonitor] push error:", err.message); }
      await new Promise(r => setTimeout(r, 50));
    }

    if (!subDeleted) {
      const newKnown     = [...knownIds.filter(id => currentIds.includes(id)), ...sentAlertIds];
      const knownChanged = newKnown.length !== knownIds.length || newKnown.some(id => !knownIds.includes(id));
      if (knownChanged) {
        await d1Query(
          "UPDATE push_subscriptions SET known_alert_ids = ?, updated_at = datetime('now') WHERE endpoint = ?",
          [JSON.stringify(newKnown), row.endpoint]
        );
      }
    }
  }

  // ── Rain (every run — GH Actions is already every 5 min) ──
  if (prefs.rainEnabled !== false) {
    try { await checkPrecipitation(row, vapid); } catch {}
  }

  // ── SPC/WPC nerd-mode ─────────────────────────────────────
  try { await checkSPCAndWPC(row, vapid); } catch {}
}

console.log("[SkyMonitor] Done.");
