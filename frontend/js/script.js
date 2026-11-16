/* SecureText frontend – talks only to the existing Flask API (same origin). */
"use strict";

// ---- API configuration: change endpoints here only ----
const API = {
  base: "",
  health: "/api/health",
  aesEnc: "/api/encrypt", aesDec: "/api/decrypt",
  rsaKeys: "/api/rsa/keys", rsaEnc: "/api/rsa/encrypt", rsaDec: "/api/rsa/decrypt",
  caesar: m => `/api/caesar/${m}`, vigenere: m => `/api/vigenere/${m}`,
  fileEnc: "/api/files/encrypt", fileDec: "/api/files/decrypt",
};
const MAX_FILE = 5 * 1024 * 1024;
const $ = id => document.getElementById(id);
let ops = 0;

// ---- Networking helpers ----
/** POST JSON or FormData; returns parsed JSON. Throws Error with API message. */
async function postJSON(url, body) {
  const isForm = body instanceof FormData;
  const res = await fetch(API.base + url, {
    method: "POST",
    headers: isForm ? {} : { "Content-Type": "application/json" },
    body: isForm ? body : JSON.stringify(body),
  });
  const text = await res.text();
  let data = {};
  try { data = JSON.parse(text); } catch { /* non-JSON body */ }
  if (!res.ok || data.success === false) {
    throw new Error(data.error || data.message || `Request failed (HTTP ${res.status})`);
  }
  return data;
}

/** POST multipart and return {blob, filename}; errors arrive as JSON. */
async function postFile(url, form, fallbackName) {
  const res = await fetch(API.base + url, { method: "POST", body: form });
  const type = res.headers.get("Content-Type") || "";
  if (!res.ok || type.includes("application/json")) {
    let err = `Request failed (HTTP ${res.status})`;
    try { const d = await res.json(); err = d.error || d.message || err; } catch { /* ignore */ }
    throw new Error(err);
  }
  const cd = res.headers.get("Content-Disposition") || "";
  const m = cd.match(/filename\*?=(?:UTF-8'')?"?([^";]+)"?/i);
  return { blob: await res.blob(), filename: m ? decodeURIComponent(m[1]) : fallbackName };
}

function saveBlob(blob, name) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

// ---- UI helpers ----
function setMsg(id, text, type) {
  const el = $(id);
  el.textContent = text || "";
  el.className = "msg" + (type ? " " + type : "");
}
function toast(text) {
  const t = document.createElement("div");
  t.className = "toast-lite"; t.textContent = text;
  $("toastWrap").appendChild(t);
  setTimeout(() => t.remove(), 2200);
}
/** Runs an async action with a busy button and error display. Never logs secrets. */
async function run(btn, msgId, action) {
  setMsg(msgId, "");
  const label = btn && btn.textContent;
  if (btn) { btn.disabled = true; btn.textContent = "Working…"; }
  try {
    await action();
    ops++; $("sOps").textContent = ops;
  } catch (e) {
    setMsg(msgId, e.message, "error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = label; }
  }
}
function show(outId, textId, value) {
  $(textId).textContent = value;
  $(outId).hidden = false;
}
const val = (form, name) => form.elements[name].value;
/** Submit button that triggered the event (used for encrypt/decrypt pairs). */
const submitter = e => e.submitter || e.target.querySelector("button");

// ---- Navigation ----
const titles = { dashboard: "Dashboard", aes: "AES-256-GCM", rsa: "RSA-2048", caesar: "Caesar cipher",
  vigenere: "Vigenère cipher", files: "File encryption", info: "Security information" };
function route() {
  const name = titles[location.hash.slice(1)] ? location.hash.slice(1) : "dashboard";
  document.querySelectorAll(".view").forEach(v => v.classList.toggle("active", v.id === "view-" + name));
  document.querySelectorAll("#nav .nav-link").forEach(a => a.classList.toggle("active", a.hash === "#" + name));
  $("pageTitle").textContent = titles[name];
  $("sidebar").classList.remove("open");
  window.scrollTo(0, 0);
}
window.addEventListener("hashchange", route);
$("menuBtn").addEventListener("click", () => $("sidebar").classList.toggle("open"));

// ---- Health check ----
async function checkHealth() {
  try {
    const res = await fetch(API.base + API.health);
    const d = await res.json();
    const ok = res.ok && d.status === "online";
    $("dot").className = "dot " + (ok ? "on" : "off");
    $("statusText").textContent = ok ? "API online" : "API unavailable";
    $("sApi").textContent = ok ? "Online" : "Offline";
  } catch {
    $("dot").className = "dot off";
    $("statusText").textContent = "API offline";
    $("sApi").textContent = "Offline";
  }
}

// ---- AES-256-GCM ----
$("aesEncForm").addEventListener("submit", e => {
  e.preventDefault();
  const f = e.target;
  run(submitter(e), "aesEncMsg", async () => {
    const d = await postJSON(API.aesEnc, { message: val(f, "message"), password: val(f, "password") });
    const meta = JSON.stringify(d.key_metadata, null, 2);
    show("aesEncOut", "aesEncData", d.encrypted_data);
    $("aesEncMeta").textContent = meta;
    // Retain both values so decryption works immediately.
    $("aesDecData").value = d.encrypted_data;
    $("aesDecMeta").value = meta;
    f.elements.password.value = "";
  });
});
$("aesDecForm").addEventListener("submit", e => {
  e.preventDefault();
  const f = e.target;
  run(submitter(e), "aesDecMsg", async () => {
    let meta;
    try { meta = JSON.parse(val(f, "key_metadata")); }
    catch { throw new Error("Key metadata must be valid JSON."); }
    const d = await postJSON(API.aesDec, {
      encrypted_data: val(f, "encrypted_data"), key_metadata: meta, password: val(f, "password") });
    show("aesDecOut", "aesDecText", d.decrypted_message);
    f.elements.password.value = "";
  });
});

// ---- RSA ----
$("rsaKeyForm").addEventListener("submit", e => {
  e.preventDefault();
  const f = e.target;
  run(submitter(e), "rsaKeyMsg", async () => {
    const pw = val(f, "password");
    if (pw.length < 12) throw new Error("Password must be at least 12 characters.");
    const d = await postJSON(API.rsaKeys, { password: pw });
    $("rsaPub").textContent = d.public_key;
    $("rsaPriv").textContent = d.encrypted_private_key;
    $("rsaKeyOut").hidden = false;
    // Pre-fill the other RSA and file forms (the private key remains password-protected).
    $("rsaEncPub").value = $("fileEncPub").value = d.public_key;
    $("rsaDecPriv").value = $("fileDecPriv").value = d.encrypted_private_key;
    f.elements.password.value = "";
  });
});
$("rsaEncForm").addEventListener("submit", e => {
  e.preventDefault();
  const f = e.target;
  run(submitter(e), "rsaEncMsg", async () => {
    const d = await postJSON(API.rsaEnc, { message: val(f, "message"), public_key: val(f, "public_key") });
    show("rsaEncOut", "rsaEncText", d.ciphertext);
    $("rsaDecCipher").value = d.ciphertext;
  });
});
$("rsaDecForm").addEventListener("submit", e => {
  e.preventDefault();
  const f = e.target;
  run(submitter(e), "rsaDecMsg", async () => {
    const d = await postJSON(API.rsaDec, {
      ciphertext: val(f, "ciphertext"), encrypted_private_key: val(f, "encrypted_private_key"),
      password: val(f, "password") });
    show("rsaDecOut", "rsaDecText", d.decrypted_message);
    f.elements.password.value = "";
  });
});

// ---- Caesar and Vigenère (one handler, two buttons) ----
function classic(formId, name, field, urlFn) {
  $(formId).addEventListener("submit", e => {
    e.preventDefault();
    const f = e.target, mode = submitter(e).dataset.mode;
    const msgId = name + "Msg";
    run(submitter(e), msgId, async () => {
      const body = { message: val(f, "message") };
      body[field] = field === "shift" ? parseInt(val(f, "shift"), 10) : val(f, "key");
      const d = await postJSON(urlFn(mode), body);
      $(name + "Label").textContent = mode === "encrypt" ? "Encrypted message" : "Decrypted message";
      show(name + "Out", name + "Text", mode === "encrypt" ? d.encrypted_message : d.decrypted_message);
    });
  });
}
classic("caesarForm", "caesar", "shift", API.caesar);
classic("vigenereForm", "vigenere", "key", API.vigenere);

// ---- Files ----
function fileHandler(formId, msgId, url, fallback) {
  $(formId).addEventListener("submit", e => {
    e.preventDefault();
    const f = e.target, file = f.elements.file.files[0];
    run(submitter(e), msgId, async () => {
      if (!file) throw new Error("Choose a file first.");
      if (file.size > MAX_FILE) throw new Error("File is larger than the 5 MB limit.");
      const { blob, filename } = await postFile(url, new FormData(f), fallback(file));
      saveBlob(blob, filename);
      setMsg(msgId, `Done. Downloaded ${filename}.`, "success");
      if (f.elements.password) f.elements.password.value = "";
    });
  });
}
fileHandler("fileEncForm", "fileEncMsg", API.fileEnc, file => file.name + ".securetext");
fileHandler("fileDecForm", "fileDecMsg", API.fileDec, () => "decrypted_file");

// ---- Copy / download buttons ----
document.addEventListener("click", e => {
  const c = e.target.closest("[data-copy]"), d = e.target.closest("[data-dl]");
  if (c) navigator.clipboard.writeText($(c.dataset.copy).textContent).then(() => toast("Copied"));
  if (d) saveBlob(new Blob([$(d.dataset.dl).textContent], { type: "text/plain" }), d.dataset.name);
});

route();
checkHealth();
setInterval(checkHealth, 30000);
