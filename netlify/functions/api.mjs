import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";
import {
  checkSetupCode, hashPassword, verifyPassword, tempPassword, sessionCookie, clearCookie, readSession,
} from "../lib/auth.mjs";

const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  });

const MAX_PHOTO = 2 * 1024 * 1024; // 2 Mo par photo (elles sont réduites avant l'envoi)
const clean = (s, max = 60) => String(s || "").replace(/\s+/g, " ").trim().slice(0, max);
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

const meta = () => getStore({ name: "trombi-meta", consistency: "strong" });
const photos = () => getStore({ name: "trombi-photos", consistency: "strong" });

async function loadIndex() {
  return (await meta().get("index", { type: "json" })) || { students: [] };
}
const saveIndex = (idx) => meta().setJSON("index", idx);

/* ---------- Comptes ---------- */
// Le super admin est le seul compte de ce rôle ; les autres sont éditeurs ou lecteurs.
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "mmakids@mmabaisieux.fr").toLowerCase();
const LEVEL = { reader: 1, editor: 2, superadmin: 3 };
const ROLE_LABEL = { reader: "lecteur", editor: "éditeur", superadmin: "super admin" };
const MIN_PASSWORD = 10;
const MAX_PENDING = 30;           // limite les inscriptions en attente (anti-spam)
const LOCK_AFTER = 5, LOCK_MS = 15 * 60 * 1000;

const normEmail = (s) => String(s || "").trim().toLowerCase().slice(0, 120);
const isEmail = (s) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);

async function loadUsers() {
  return (await meta().get("users", { type: "json" })) || { users: [] };
}
const saveUsers = (u) => meta().setJSON("users", u);
// Ce que le super admin voit d'un compte : jamais le hash du mot de passe
const publicUser = ({ pwHash, ...u }) => u;

/* ---------- Journal des actions ---------- */
async function log(user, action) {
  const j = (await meta().get("journal", { type: "json" })) || { entries: [] };
  j.entries.unshift({ t: Date.now(), by: user?.email || "?", action });
  j.entries = j.entries.slice(0, 2000);
  await meta().setJSON("journal", j);
}

/* ---------- Fiches détaillées : chiffrées au repos (AES-256-GCM) avec DATA_KEY ---------- */
const FICHE_FIELDS = ["lastName", "birthDate", "birthPlace", "address", "postcode", "city", "phone", "email",
  "emergencyContact", "emergencyPhone", "emergencyEmail", "license", "health"];
const FIELD_LABEL = {
  name: "prénom", className: "classe", noPhotoRights: "droit à l'image", whatsapp: "WhatsApp",
  lastName: "nom", birthDate: "date de naissance", birthPlace: "lieu de naissance", address: "adresse",
  postcode: "code postal", city: "ville", phone: "téléphone", email: "e-mail", emergencyContact: "personne à prévenir",
  emergencyPhone: "téléphone d'urgence", emergencyEmail: "e-mail d'urgence", license: "licence", health: "santé",
};

function dataKey() {
  const k = process.env.DATA_KEY || "";
  if (k.length < 16) throw new Error("DATA_KEY manquant ou trop court (16 caractères minimum) dans les variables Netlify.");
  return crypto.createHash("sha256").update("trombi-data:" + k).digest();
}
function encryptFiche(obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", dataKey(), iv);
  const ct = Buffer.concat([c.update(JSON.stringify(obj), "utf8"), c.final()]);
  return { iv: iv.toString("base64"), ct: ct.toString("base64"), tag: c.getAuthTag().toString("base64") };
}
function decryptFiche(e) {
  const d = crypto.createDecipheriv("aes-256-gcm", dataKey(), Buffer.from(e.iv, "base64"));
  d.setAuthTag(Buffer.from(e.tag, "base64"));
  return JSON.parse(Buffer.concat([d.update(Buffer.from(e.ct, "base64")), d.final()]).toString("utf8"));
}
// Garde uniquement les champs connus, en texte court ; null si la fiche est vide
function cleanFiche(f) {
  if (!f || typeof f !== "object") return null;
  const out = {};
  for (const k of FICHE_FIELDS) {
    const v = String(f[k] ?? "").trim().slice(0, k === "health" ? 1000 : 200);
    if (v) out[k] = v;
  }
  return Object.keys(out).length ? out : null;
}
// Version envoyée au navigateur. Tout le monde reçoit l'initiale du nom (« Jean D. ») ;
// seuls les éditeurs et le super admin reçoivent la fiche détaillée, en clair.
function studentFor(role, { ficheEnc, secure, ...s }) {
  let fiche = null, ficheError = false;
  if (ficheEnc) {
    try { fiche = decryptFiche(ficheEnc); }
    catch (e) { console.error("Fiche illisible", s.id, e.message); ficheError = true; }
  }
  const out = { ...s };
  const initial = (fiche?.lastName || "").trim().charAt(0).toUpperCase();
  if (initial) out.initial = initial;
  if (LEVEL[role] >= LEVEL.editor) {
    if (fiche) out.fiche = fiche;
    if (ficheError) out.ficheError = true;
  }
  return out;
}

// Le site envoie de vrais formulaires (pour que le navigateur retienne le mot de passe), le script du JSON
async function readBody(req) {
  if (/form/.test(req.headers.get("content-type") || "")) {
    const f = await req.formData().catch(() => null);
    return f ? Object.fromEntries(f) : {};
  }
  return (await req.json().catch(() => ({}))) || {};
}

const LOGIN_ERRORS = {
  identifiants: "E-mail ou mot de passe incorrect",
  attente: "Ton compte attend la validation du super admin",
  revoque: "Ce compte a été désactivé",
  bloque: "Trop d'essais : réessaie dans 15 minutes",
};

export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/?/, "");
  const method = req.method;

  try {
    /* ===== Routes publiques ===== */

    // Connexion
    if (path === "login" && method === "POST") {
      const isForm = /form/.test(req.headers.get("content-type") || "");
      const body = await readBody(req);
      const email = normEmail(body.email);
      const store = await loadUsers();
      const u = store.users.find((x) => x.email === email);
      const now = Date.now();
      let err = null;
      if (u && u.lockedUntil > now) err = "bloque";
      else if (!(await verifyPassword(body.password, u?.pwHash))) {
        err = "identifiants";
        if (u) {
          u.failed = (u.failed || 0) + 1;
          if (u.failed >= LOCK_AFTER) { u.lockedUntil = now + LOCK_MS; u.failed = 0; }
          await saveUsers(store);
        }
        await delay(800);
      } else if (u.status === "pending") err = "attente";
      else if (u.status !== "active") err = "revoque";

      if (!err) {
        u.failed = 0; u.lockedUntil = 0; u.lastLogin = now;
        await saveUsers(store);
        await log(u, "connexion");
      }
      if (isForm) {
        const headers = { location: err ? `/?erreur=${err}` : "/", "cache-control": "no-store" };
        if (!err) headers["set-cookie"] = sessionCookie(u);
        return new Response(null, { status: 303, headers });
      }
      if (err) return json({ error: LOGIN_ERRORS[err] }, 401);
      return json({ ok: true, mustChangePassword: !!u.mustChangePassword }, 200, { "set-cookie": sessionCookie(u) });
    }

    if (path === "logout" && method === "POST") {
      return json({ ok: true }, 200, { "set-cookie": clearCookie() });
    }

    // Demande de compte : en attente jusqu'à validation par le super admin.
    // Le compte super admin se crée avec le code de mise en route (ancien code du site).
    if (path === "register" && method === "POST") {
      const body = await readBody(req);
      const name = clean(body.name);
      const email = normEmail(body.email);
      const password = String(body.password || "");
      if (!name) return json({ error: "Indique ton nom" }, 400);
      if (!isEmail(email)) return json({ error: "Adresse e-mail invalide" }, 400);
      if (password.length < MIN_PASSWORD) return json({ error: `Mot de passe trop court (${MIN_PASSWORD} caractères minimum)` }, 400);

      const store = await loadUsers();
      const sent = { ok: true, message: "Demande envoyée. Le super admin doit valider ton compte avant ta première connexion." };
      if (store.users.some((x) => x.email === email)) return json(sent); // ne révèle pas si l'e-mail existe

      const base = {
        id: crypto.randomUUID(), email, name, pwHash: await hashPassword(password),
        created: Date.now(), sessionVersion: 0,
      };
      if (email === ADMIN_EMAIL) {
        if (store.users.some((x) => x.role === "superadmin")) return json(sent);
        if (!body.setupCode) return json({ error: "Code de mise en route requis pour ce compte", needSetup: true }, 409);
        if (!checkSetupCode(body.setupCode)) { await delay(1500); return json({ error: "Code de mise en route incorrect", needSetup: true }, 403); }
        store.users.push({ ...base, role: "superadmin", status: "active" });
        await saveUsers(store);
        await log({ email }, "création du compte super admin");
        return json({ ok: true, message: "Compte super admin créé : tu peux te connecter." });
      }
      if (store.users.filter((x) => x.status === "pending").length >= MAX_PENDING)
        return json({ error: "Trop de demandes en attente, réessaie plus tard" }, 429);
      store.users.push({ ...base, role: null, status: "pending" });
      await saveUsers(store);
      await log({ email }, "demande de compte");
      return json(sent);
    }

    // Mot de passe oublié : signale la demande au super admin (pas d'e-mail envoyé)
    if (path === "forgot" && method === "POST") {
      const body = await readBody(req);
      const email = normEmail(body.email);
      const store = await loadUsers();
      const u = store.users.find((x) => x.email === email && x.status === "active");
      if (u && u.role !== "superadmin") {
        u.resetRequested = Date.now();
        await saveUsers(store);
        await log(u, "mot de passe oublié signalé");
      }
      return json({ ok: true, message: "Demande transmise au super admin : il te donnera un mot de passe temporaire." });
    }

    /* ===== Tout le reste exige une session valide ===== */
    const sess = readSession(req);
    const store = await loadUsers();
    const me = sess && store.users.find((x) => x.id === sess.id);
    if (!me || me.status !== "active" || (me.sessionVersion || 0) !== sess.ver)
      return json({ error: "Non connecté" }, 401, { "set-cookie": clearCookie() });
    const can = (role) => LEVEL[me.role] >= LEVEL[role];
    const forbidden = () => json({ error: "Action non autorisée pour ton compte" }, 403);

    if (path === "me" && method === "GET") {
      return json({ id: me.id, email: me.email, name: me.name, role: me.role, mustChangePassword: !!me.mustChangePassword });
    }

    // Changement de mot de passe (obligatoire après un mot de passe temporaire)
    if (path === "password" && method === "POST") {
      const body = await readBody(req);
      const next = String(body.newPassword || "");
      if (!(await verifyPassword(body.currentPassword, me.pwHash))) { await delay(800); return json({ error: "Mot de passe actuel incorrect" }, 400); }
      if (next.length < MIN_PASSWORD) return json({ error: `Nouveau mot de passe trop court (${MIN_PASSWORD} caractères minimum)` }, 400);
      if (next === body.currentPassword) return json({ error: "Choisis un mot de passe différent" }, 400);
      me.pwHash = await hashPassword(next);
      me.mustChangePassword = false;
      me.sessionVersion = (me.sessionVersion || 0) + 1; // déconnecte les autres appareils
      await saveUsers(store);
      await log(me, "changement de mot de passe");
      return json({ ok: true }, 200, { "set-cookie": sessionCookie(me) });
    }

    if (me.mustChangePassword) return json({ error: "Change d'abord ton mot de passe", mustChangePassword: true }, 403);

    /* ----- Élèves ----- */
    if (path === "students" && method === "GET") {
      const idx = await loadIndex();
      return json({ students: idx.students.map((s) => studentFor(me.role, s)) });
    }

    // Ajout d'un élève : formulaire avec name, className, photo, noPhotoRights, whatsapp
    if (path === "students" && method === "POST") {
      if (!can("editor")) return forbidden();
      const form = await req.formData();
      const name = clean(form.get("name"));
      const className = clean(form.get("className"), 40);
      const photo = form.get("photo");
      if (!name || !className) return json({ error: "Prénom et classe obligatoires" }, 400);
      if (!photo || typeof photo === "string" || !/^image\/(jpeg|png|webp)$/.test(photo.type))
        return json({ error: "Photo manquante ou format non accepté" }, 400);
      if (photo.size > MAX_PHOTO) return json({ error: "Photo trop lourde" }, 400);

      const id = crypto.randomUUID();
      await photos().set(id, await photo.arrayBuffer(), { metadata: { type: photo.type } });
      const idx = await loadIndex();
      const student = {
        id, name, className, added: Date.now(),
        noPhotoRights: form.get("noPhotoRights") === "1",
        whatsapp: form.get("whatsapp") === "1",
      };
      idx.students.push(student);
      await saveIndex(idx);
      await log(me, `ajout de ${name} (${className})`);
      return json(studentFor(me.role, student), 201);
    }

    // Modifier / supprimer un élève
    const m = path.match(/^students\/([\w-]{36})$/);
    if (m && method === "PATCH") {
      if (!can("editor")) return forbidden();
      const body = await req.json().catch(() => ({}));
      const idx = await loadIndex();
      const s = idx.students.find((x) => x.id === m[1]);
      if (!s) return json({ error: "Élève introuvable" }, 404);
      const changed = [];
      const set = (k, v) => { if (s[k] !== v) { s[k] = v; changed.push(FIELD_LABEL[k]); } };
      if (body.name !== undefined && clean(body.name)) set("name", clean(body.name));
      if (body.className !== undefined && clean(body.className, 40)) set("className", clean(body.className, 40));
      if (typeof body.noPhotoRights === "boolean") set("noPhotoRights", body.noPhotoRights);
      if (typeof body.whatsapp === "boolean") set("whatsapp", body.whatsapp);
      if (body.fiche !== undefined) {
        const old = s.ficheEnc ? decryptFiche(s.ficheEnc) : {}; // refuse d'écraser une fiche illisible (DATA_KEY absente ou changée)
        const f = cleanFiche(body.fiche);
        for (const k of FICHE_FIELDS) if ((old[k] || "") !== (f?.[k] || "")) changed.push(FIELD_LABEL[k]);
        if (f) s.ficheEnc = encryptFiche(f); else delete s.ficheEnc;
        delete s.secure; // ancien format chiffré dans le navigateur, abandonné
      }
      await saveIndex(idx);
      if (changed.length) await log(me, `modification de ${s.name} : ${changed.join(", ")}`);
      return json(studentFor(me.role, s));
    }
    if (m && method === "DELETE") {
      if (!can("editor")) return forbidden();
      const idx = await loadIndex();
      const s = idx.students.find((x) => x.id === m[1]);
      idx.students = idx.students.filter((x) => x.id !== m[1]);
      await saveIndex(idx);
      await photos().delete(m[1]);
      if (s) await log(me, `suppression de ${s.name} (${s.className})`);
      return json({ ok: true });
    }

    // Photo d'un élève
    const p = path.match(/^photo\/([\w-]{36})$/);
    if (p && method === "GET") {
      const res = await photos().getWithMetadata(p[1], { type: "arrayBuffer" });
      if (!res) return new Response("Introuvable", { status: 404 });
      return new Response(res.data, {
        headers: {
          "content-type": res.metadata?.type || "image/jpeg",
          "cache-control": "private, max-age=3600",
        },
      });
    }

    /* ----- Administration des comptes (super admin) ----- */
    if (path === "users" || path.startsWith("users/") || path === "journal") {
      if (!can("superadmin")) return forbidden();
    }

    if (path === "users" && method === "GET") {
      return json({ users: store.users.map(publicUser) });
    }

    const u = path.match(/^users\/([\w-]{36})(\/reset)?$/);
    if (u) {
      const target = store.users.find((x) => x.id === u[1]);
      if (!target) return json({ error: "Compte introuvable" }, 404);
      if (target.id === me.id) return json({ error: "Tu ne peux pas modifier ton propre compte ici" }, 400);
      const who = `${target.name} <${target.email}>`;

      // Valider, changer de rôle, révoquer, réactiver
      if (!u[2] && method === "PATCH") {
        const body = await req.json().catch(() => ({}));
        const role = body.role ?? target.role;
        const status = body.status ?? target.status;
        if (!["editor", "reader"].includes(role)) return json({ error: "Rôle invalide" }, 400);
        if (!["active", "revoked"].includes(status)) return json({ error: "Statut invalide" }, 400);
        const before = { role: target.role, status: target.status };
        target.role = role;
        target.status = status;
        if (status === "revoked" && before.status !== "revoked") target.sessionVersion = (target.sessionVersion || 0) + 1;
        await saveUsers(store);
        const what = before.status === "pending" ? `validation du compte ${who} (${ROLE_LABEL[role]})`
          : status === "revoked" && before.status !== "revoked" ? `révocation du compte ${who}`
          : status === "active" && before.status === "revoked" ? `réactivation du compte ${who} (${ROLE_LABEL[role]})`
          : `rôle de ${who} : ${ROLE_LABEL[role]}`;
        await log(me, what);
        return json(publicUser(target));
      }

      // Nouveau mot de passe temporaire, à changer à la prochaine connexion
      if (u[2] && method === "POST") {
        const temp = tempPassword();
        target.pwHash = await hashPassword(temp);
        target.mustChangePassword = true;
        target.resetRequested = null;
        target.failed = 0;
        target.lockedUntil = 0;
        target.sessionVersion = (target.sessionVersion || 0) + 1;
        await saveUsers(store);
        await log(me, `mot de passe temporaire pour ${who}`);
        return json({ tempPassword: temp, user: publicUser(target) });
      }

      // Supprimer (demande refusée ou compte révoqué)
      if (!u[2] && method === "DELETE") {
        store.users = store.users.filter((x) => x.id !== target.id);
        await saveUsers(store);
        await log(me, `suppression du compte ${who}`);
        return json({ ok: true });
      }
    }

    if (path === "journal" && method === "GET") {
      const j = (await meta().get("journal", { type: "json" })) || { entries: [] };
      return json({ entries: j.entries.slice(0, 300) });
    }

    return json({ error: "Route inconnue" }, 404);
  } catch (e) {
    console.error(e);
    return json({ error: e.message || "Erreur serveur" }, 500);
  }
};

export const config = { path: "/api/*" };
