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

// Fiches détaillées : chiffrées dans le navigateur (AES-GCM), le serveur ne voit que du chiffré.
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const isCipher = (c) =>
  c && typeof c === "object" && typeof c.iv === "string" && typeof c.ct === "string" &&
  c.iv.length <= 32 && c.ct.length <= 20000 && B64.test(c.iv) && B64.test(c.ct);

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

    // Coffre des fiches détaillées : sel + valeur témoin pour vérifier la phrase secrète
    if (path === "vault" && method === "GET") {
      return json((await meta().get("vault", { type: "json" })) || null);
    }
    if (path === "vault" && method === "PUT") {
      if (await meta().get("vault")) return json({ error: "La phrase secrète existe déjà" }, 409);
      const v = await req.json().catch(() => ({}));
      if (typeof v.salt !== "string" || !B64.test(v.salt) || !Number.isInteger(v.iter) || v.iter < 100000 || !isCipher(v.check))
        return json({ error: "Données invalides" }, 400);
      const vault = { salt: v.salt, iter: v.iter, check: { iv: v.check.iv, ct: v.check.ct } };
      await meta().setJSON("vault", vault);
      return json(vault, 201);
    }

    // Liste des élèves
    if (path === "students" && method === "GET") {
      return json(await loadIndex());
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
      if (body.secure === null) delete s.secure;
      else if (body.secure !== undefined) {
        if (!isCipher(body.secure)) return json({ error: "Fiche chiffrée invalide" }, 400);
        s.secure = { iv: body.secure.iv, ct: body.secure.ct };
      }
      await saveIndex(idx);
      return json(s);
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
