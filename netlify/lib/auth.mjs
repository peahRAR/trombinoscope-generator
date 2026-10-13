import crypto from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(crypto.scrypt);
const COOKIE = "trombi_session";
const DURATION_S = 12 * 60 * 60; // 12 heures

// Les sessions sont signées avec une clé dérivée de DATA_KEY (déjà obligatoire pour les fiches).
function key() {
  const k = process.env.DATA_KEY || "";
  if (k.length < 16) throw new Error("DATA_KEY manquant ou trop court (16 caractères minimum) dans les variables Netlify.");
  return crypto.createHash("sha256").update("trombi-session:" + k).digest();
}

const sign = (v) => crypto.createHmac("sha256", key()).update(v).digest("base64url");

function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// Code de mise en route : l'ancien code du site (SITE_PASSWORD), demandé une seule fois
// pour créer le compte super admin.
export function checkSetupCode(given) {
  const code = process.env.SITE_PASSWORD || "";
  return code.length >= 6 && safeEqual(given || "", code);
}

/* ---------- Mots de passe (scrypt, sel aléatoire) ---------- */
const SCRYPT = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(String(pw).normalize("NFC"), salt, 32, SCRYPT);
  return `scrypt$${salt.toString("base64")}$${hash.toString("base64")}`;
}

export async function verifyPassword(pw, stored) {
  // Sans compte, on calcule quand même un hash : même durée de réponse, l'existence d'un e-mail ne se devine pas
  if (!stored) { await hashPassword(pw || ""); return false; }
  const [, salt, hash] = stored.split("$");
  const got = await scrypt(String(pw || "").normalize("NFC"), Buffer.from(salt, "base64"), 32, SCRYPT);
  return crypto.timingSafeEqual(got, Buffer.from(hash, "base64"));
}

// Mot de passe temporaire lisible, sans caractères ambigus : « abcd-efgh-jkmn »
export function tempPassword() {
  const A = "abcdefghjkmnpqrstuvwxyz23456789";
  const pick = () => Array.from(crypto.randomBytes(4), (b) => A[b % A.length]).join("");
  return `${pick()}-${pick()}-${pick()}`;
}

/* ---------- Sessions : cookie signé « id.expiration.version.signature » ---------- */
// La version est incrémentée à la révocation ou au changement de mot de passe : les anciennes sessions tombent.
export function sessionCookie(user) {
  const exp = Math.floor(Date.now() / 1000) + DURATION_S;
  const v = `${user.id}.${exp}.${user.sessionVersion || 0}`;
  return `${COOKIE}=${v}.${sign(v)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${DURATION_S}`;
}

export const clearCookie = () => `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

export function readSession(req) {
  const raw = req.headers.get("cookie") || "";
  const m = raw.match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  if (!m) return null;
  const parts = m[1].split(".");
  if (parts.length !== 4) return null;
  const [id, exp, ver, sig] = parts;
  if (Number(exp) < Date.now() / 1000) return null;
  if (!safeEqual(sig, sign(`${id}.${exp}.${ver}`))) return null;
  return { id, ver: Number(ver) };
}
