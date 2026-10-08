import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";
import { checkPassword, sessionCookie, clearCookie, isLoggedIn } from "../lib/auth.mjs";

const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  });

const MAX_PHOTO = 2 * 1024 * 1024; // 2 Mo par photo (elles sont réduites avant l'envoi)
const clean = (s, max = 60) => String(s || "").replace(/\s+/g, " ").trim().slice(0, max);

const meta = () => getStore({ name: "trombi-meta", consistency: "strong" });
const photos = () => getStore({ name: "trombi-photos", consistency: "strong" });

async function loadIndex() {
  return (await meta().get("index", { type: "json" })) || { students: [] };
}
const saveIndex = (idx) => meta().setJSON("index", idx);

// Fiches détaillées : chiffrées au repos (AES-256-GCM) avec DATA_KEY, déchiffrées pour les personnes connectées.
const FICHE_FIELDS = ["lastName", "birthDate", "birthPlace", "address", "postcode", "city", "phone", "email",
  "emergencyContact", "emergencyPhone", "emergencyEmail", "license", "health"];

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
// Version envoyée au navigateur : fiche en clair, jamais le chiffré.
// Si DATA_KEY manque ou a changé, le trombinoscope reste visible et la fiche est signalée illisible.
function publicStudent({ ficheEnc, secure, ...s }) {
  if (!ficheEnc) return s;
  try { return { ...s, fiche: decryptFiche(ficheEnc) }; }
  catch (e) { console.error("Fiche illisible", s.id, e.message); return { ...s, ficheError: true }; }
}

export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/?/, "");
  const method = req.method;

  try {
    // --- Connexion ---
    if (path === "login" && method === "POST") {
      const { password } = await req.json().catch(() => ({}));
      if (!checkPassword(password)) {
        await new Promise((r) => setTimeout(r, 1500)); // ralentit les essais au hasard
        return json({ error: "Code incorrect" }, 401);
      }
      return json({ ok: true }, 200, { "set-cookie": sessionCookie() });
    }
    if (path === "logout" && method === "POST") {
      return json({ ok: true }, 200, { "set-cookie": clearCookie() });
    }

    // --- Tout le reste exige d'être connecté ---
    if (!isLoggedIn(req)) return json({ error: "Non connecté" }, 401);

    // Liste des élèves
    if (path === "students" && method === "GET") {
      const idx = await loadIndex();
      return json({ students: idx.students.map(publicStudent) });
    }

    // Ajout d'un élève : formulaire avec name, className, photo, noPhotoRights, whatsapp
    if (path === "students" && method === "POST") {
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
      return json(student, 201);
    }

    // Modifier / supprimer un élève
    const m = path.match(/^students\/([\w-]{36})$/);
    if (m && method === "PATCH") {
      const body = await req.json().catch(() => ({}));
      const idx = await loadIndex();
      const s = idx.students.find((x) => x.id === m[1]);
      if (!s) return json({ error: "Élève introuvable" }, 404);
      if (body.name !== undefined && clean(body.name)) s.name = clean(body.name);
      if (body.className !== undefined && clean(body.className, 40)) s.className = clean(body.className, 40);
      if (typeof body.noPhotoRights === "boolean") s.noPhotoRights = body.noPhotoRights;
      if (typeof body.whatsapp === "boolean") s.whatsapp = body.whatsapp;
      if (body.fiche !== undefined) {
        if (s.ficheEnc) decryptFiche(s.ficheEnc); // refuse d'écraser une fiche illisible (DATA_KEY absente ou changée)
        const f = cleanFiche(body.fiche);
        if (f) s.ficheEnc = encryptFiche(f); else delete s.ficheEnc;
        delete s.secure; // ancien format chiffré dans le navigateur, abandonné
      }
      await saveIndex(idx);
      return json(publicStudent(s));
    }
    if (m && method === "DELETE") {
      const idx = await loadIndex();
      idx.students = idx.students.filter((x) => x.id !== m[1]);
      await saveIndex(idx);
      await photos().delete(m[1]);
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

    return json({ error: "Route inconnue" }, 404);
  } catch (e) {
    console.error(e);
    return json({ error: e.message || "Erreur serveur" }, 500);
  }
};

export const config = { path: "/api/*" };
