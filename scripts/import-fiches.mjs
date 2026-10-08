// Import des fiches de renseignement (.docx) dans les fiches détaillées chiffrées.
//
//   node scripts/import-fiches.mjs <dossier>            simulation : n'écrit rien
//   node scripts/import-fiches.mjs <dossier> --apply    enregistre sur le site
//
// À mettre dans .env (jamais commité) :
//   SITE_URL=https://ton-site.netlify.app
//   SITE_PASSWORD=le code d'accès du site
// La phrase secrète des fiches est demandée au lancement (ou FICHES_PASSPHRASE dans l'environnement).
//
// Le script n'affiche aucune donnée personnelle hormis le prénom et le nom du fichier.
// Il ne crée pas d'élève : il complète ceux déjà présents, reconnus par leur prénom.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, basename } from "node:path";
import readline from "node:readline";

const VAULT_CHECK = "trombi-fiches-v1";

/* ---------- Paramètres ---------- */
const args = process.argv.slice(2);
const APPLY = args.includes("--apply");
const dir = args.find((a) => !a.startsWith("--"));
if (!dir || !existsSync(dir)) {
  console.error("Usage : node scripts/import-fiches.mjs <dossier> [--apply]");
  process.exit(1);
}
const env = { ...readEnv(".env"), ...process.env };
const SITE = (env.SITE_URL || "").replace(/\/+$/, "");
if (!SITE || !env.SITE_PASSWORD) {
  console.error("SITE_URL et SITE_PASSWORD doivent être définis dans .env");
  process.exit(1);
}

function readEnv(file) {
  if (!existsSync(file)) return {};
  const out = {};
  for (const line of readFileSync(file, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m) out[m[1]] = m[2].replace(/^(['"])(.*)\1$/, "$2");
  }
  return out;
}

/* ---------- Lecture d'une fiche .docx ---------- */
const decode = (s) =>
  s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");

function parseDocx(file) {
  const xml = execFileSync("unzip", ["-p", file, "word/document.xml"], { maxBuffer: 50 * 1024 * 1024 }).toString("utf8");
  const lines = [...xml.matchAll(/<w:p[ >][\s\S]*?<\/w:p>/g)]
    .map((p) => decode([...p[0].matchAll(/<w:t(?: [^>]*)?>([^<]*)<\/w:t>/g)].map((t) => t[1]).join("")))
    .map((t) => t.replace(/\s+/g, " ").trim())
    .filter(Boolean);

  const f = {};
  let emergency = false; // les champs après « Personne à prévenir » concernent le contact d'urgence
  const val = (line) => line.slice(line.indexOf(":") + 1).trim();
  for (const line of lines) {
    const l = line.toLowerCase();
    if (/^nom\s*:/.test(l)) f.lastName = val(line);
    else if (/^pr[ée]nom\s*:/.test(l)) f.firstName = val(line);
    else if (/^date de naissance\s*:/.test(l)) f.birthDate = val(line);
    else if (/^lieu de naissance\s*:/.test(l)) f.birthPlace = val(line);
    else if (/^adresse\s*:/.test(l)) f.address = val(line);
    else if (/^code postal\s*:/.test(l)) {
      const m = line.match(/code postal\s*:\s*(.*?)\s*ville\s*:\s*(.*)$/i);
      if (m) { f.postcode = m[1]; f.city = m[2]; } else f.postcode = val(line);
    } else if (/^ville\s*:/.test(l)) f.city = val(line);
    else if (/^personne [àa] pr[ée]venir/.test(l)) { emergency = true; f.emergencyContact = val(line); }
    else if (/^t[ée]l[ée]phone d.urgence\s*:/.test(l)) f.emergencyPhone = val(line);
    else if (/^t[ée]l[ée]phone\s*:/.test(l)) f[emergency ? "emergencyPhone" : "phone"] = val(line);
    else if (/^e-?mail\s*:/.test(l)) f[emergency ? "emergencyEmail" : "email"] = val(line);
  }
  for (const k of Object.keys(f)) if (!f[k]) delete f[k];

  // Images : logo du club (titre « logo… »), photo de l'enfant (la plus grande),
  // et toute image supplémentaire = panneau « pas de droit à l'image » posé sur la photo.
  const images = [];
  for (const d of xml.matchAll(/<w:drawing>[\s\S]*?<\/w:drawing>/g)) {
    const ext = d[0].match(/<wp:extent cx="(\d+)" cy="(\d+)"/);
    const pr = d[0].match(/<wp:docPr [^>]*>/)?.[0] || "";
    images.push({ area: ext ? Number(ext[1]) * Number(ext[2]) : 0, logo: /logo/i.test(pr) });
  }
  for (const v of xml.matchAll(/<v:shape [\s\S]*?<\/v:shape>/g)) {
    if (!/<v:imagedata /.test(v[0])) continue;
    images.push({ area: 0, logo: /o:title="[^"]*logo/i.test(v[0]) });
  }
  const others = images.filter((i) => !i.logo).sort((a, b) => b.area - a.area);
  return { fields: f, hasPhoto: others.length > 0, noPhotoRights: others.length > 1 };
}

/* ---------- Chiffrement (identique au site) ---------- */
const b64 = (buf) => Buffer.from(buf).toString("base64");
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
async function deriveKey(pass, salt, iter) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass.normalize("NFC")), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt: unb64(salt), iterations: iter, hash: "SHA-256" }, base,
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function seal(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(obj)));
  return { iv: b64(iv), ct: b64(ct) };
}
async function unseal(key, c) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(c.iv) }, key, unb64(c.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

/* ---------- Site ---------- */
let cookie = "";
async function api(path, opts = {}) {
  const r = await fetch(`${SITE}/api/${path}`, { ...opts, headers: { ...(opts.headers || {}), cookie } });
  const sc = r.headers.get("set-cookie");
  if (sc) cookie = sc.split(";")[0];
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${path} : ${body?.error || r.status}`);
  return body;
}

function askHidden(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s.includes(question)) rl.output.write(s); };
    rl.question(question, (a) => { rl.close(); process.stdout.write("\n"); resolve(a); });
  });
}

const norm = (s) => String(s || "").normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();

/* ---------- Programme ---------- */
const files = readdirSync(dir).filter((f) => /\.docx$/i.test(f) && !f.startsWith("~$")).map((f) => join(dir, f));
if (!files.length) { console.error("Aucun fichier .docx dans " + dir); process.exit(1); }

await api("login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password: env.SITE_PASSWORD }) });
const { students = [] } = await api("students");
const vault = await api("vault");
if (!vault) { console.error("Crée d'abord la phrase secrète depuis le site (bouton « Déverrouiller les fiches »)."); process.exit(1); }

const pass = env.FICHES_PASSPHRASE || (await askHidden("Phrase secrète des fiches : "));
const key = await deriveKey(pass, vault.salt, vault.iter);
const ok = await unseal(key, vault.check).then((v) => v.check === VAULT_CHECK, () => false);
if (!ok) { console.error("Phrase secrète incorrecte."); process.exit(1); }

const report = { updated: [], unchanged: [], notFound: [], ambiguous: [], unreadable: [], noPhotoRights: [], rightsMismatch: [] };
const byStudent = new Map(); // id élève -> fichiers qui le visent

const parsed = [];
for (const file of files) {
  const name = basename(file);
  let p;
  try { p = parseDocx(file); } catch { report.unreadable.push(name); continue; }
  if (!p.fields.firstName) { report.unreadable.push(name + " (prénom introuvable)"); continue; }
  const matches = students.filter((s) => norm(s.name) === norm(p.fields.firstName));
  if (!matches.length) { report.notFound.push(`${p.fields.firstName} — ${name}`); continue; }
  if (matches.length > 1) {
    report.ambiguous.push(`${p.fields.firstName} — ${name} (${matches.map((s) => s.className).join(", ")})`);
    continue;
  }
  parsed.push({ name, p, s: matches[0] });
  byStudent.set(matches[0].id, [...(byStudent.get(matches[0].id) || []), name]);
}

for (const { name, p, s } of parsed) {
  if (byStudent.get(s.id).length > 1) {
    report.ambiguous.push(`${p.fields.firstName} — plusieurs fiches : ${byStudent.get(s.id).join(", ")}`);
    continue;
  }
  let data = {};
  if (s.secure) {
    try { data = await unseal(key, s.secure); }
    catch { report.unreadable.push(`${s.name} : fiche existante illisible avec cette phrase`); continue; }
  }
  const { firstName, ...fields } = p.fields;
  const merged = { ...data, ...fields };
  const changed = JSON.stringify(merged) !== JSON.stringify(data);
  const setRights = p.noPhotoRights && !s.noPhotoRights;
  if (p.noPhotoRights) report.noPhotoRights.push(s.name);
  if (!p.noPhotoRights && s.noPhotoRights) report.rightsMismatch.push(`${s.name} — ${name}`);

  if (!changed && !setRights) { report.unchanged.push(s.name); continue; }
  if (APPLY) {
    const body = {};
    if (changed) body.secure = await seal(key, merged);
    if (setRights) body.noPhotoRights = true;
    await api("students/" + s.id, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  }
  report.updated.push(`${s.name} (${s.className})${setRights ? " + pas de droit à l'image" : ""}`);
}

const section = (title, list) => { if (list.length) console.log(`\n${title} (${list.length})\n  - ${list.join("\n  - ")}`); };
console.log(`\n${files.length} fiche(s) lue(s), ${students.length} élève(s) sur le site.`);
section(APPLY ? "Mis à jour" : "Seraient mis à jour", report.updated);
section("Déjà à jour", report.unchanged);
section("Panneau « pas de droit à l'image » détecté", report.noPhotoRights);
section("Coché « pas de droit à l'image » sur le site mais pas de panneau dans la fiche (laissé tel quel)", report.rightsMismatch);
section("Prénom introuvable sur le site", report.notFound);
section("À vérifier à la main (plusieurs correspondances)", report.ambiguous);
section("Fichiers illisibles", report.unreadable);
if (!APPLY) console.log("\nSimulation : rien n'a été enregistré. Relance avec --apply pour enregistrer.");
