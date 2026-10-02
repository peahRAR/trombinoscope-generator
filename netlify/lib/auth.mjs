import crypto from "node:crypto";

const COOKIE = "trombi_session";
const DURATION_S = 12 * 60 * 60; // 12 heures

function key() {
  const pwd = process.env.SITE_PASSWORD || "";
  if (pwd.length < 6) throw new Error("SITE_PASSWORD manquant ou trop court (6 caractères minimum).");
  return crypto.createHash("sha256").update("trombi-session:" + pwd).digest();
}

const sign = (v) => crypto.createHmac("sha256", key()).update(v).digest("base64url");

function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

export function checkPassword(given) {
  return safeEqual(given || "", process.env.SITE_PASSWORD || "") && (process.env.SITE_PASSWORD || "").length >= 6;
}

export function sessionCookie() {
  const exp = String(Math.floor(Date.now() / 1000) + DURATION_S);
  return `${COOKIE}=${exp}.${sign(exp)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${DURATION_S}`;
}

export const clearCookie = () => `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

export function isLoggedIn(req) {
  const raw = req.headers.get("cookie") || "";
  const m = raw.match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  if (!m) return false;
  const [exp, sig] = m[1].split(".");
  if (!exp || !sig || Number(exp) < Date.now() / 1000) return false;
  return safeEqual(sig, sign(exp));
}
