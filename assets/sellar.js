/* CURI MUNDO · sellado del código de autorización de Google (ver social/seal.py).
   ECDH P-256 efímero + HKDF-SHA256 (salt = state, info = "curimundo-seal-v1") + AES-256-GCM (AAD = state).
   Sin red: la CSP de la página prohíbe cualquier conexión. Los datos llegan en el fragmento #, que no sale del navegador. */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var enc = new TextEncoder();
  function b64d(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function b64e(buf) {
    var b = new Uint8Array(buf), s = "";
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  var p = new URLSearchParams(location.hash.slice(1));
  var state = p.get("s") || "", pub = p.get("k") || "", auth = "";
  try { auth = new TextDecoder().decode(b64d(p.get("a") || "")); } catch (e) { auth = ""; }
  // Quita los datos de la barra y del historial en cuanto se leen.
  try { history.replaceState(null, "", location.pathname); } catch (e) { /* sin historial */ }

  var okAuth = auth.indexOf("https://accounts.google.com/o/oauth2/") === 0 &&
    new URL(auth).searchParams.get("state") === state;
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(state) || !/^[A-Za-z0-9_-]{80,100}$/.test(pub) || !okAuth) {
    $("bad").hidden = false;
    return;
  }
  if (!window.crypto || !crypto.subtle) { $("nocrypto").hidden = false; return; }
  $("go").href = auth;
  $("steps").hidden = false;

  function fail(msg) { var e = $("err"); e.textContent = msg; e.hidden = false; }

  async function seal(text) {
    var peer = await crypto.subtle.importKey("raw", b64d(pub), { name: "ECDH", namedCurve: "P-256" }, false, []);
    var eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    var shared = await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, eph.privateKey, 256);
    var ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    var key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: enc.encode(state), info: enc.encode("curimundo-seal-v1") },
      ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: enc.encode(state) }, key, enc.encode(text));
    var epk = await crypto.subtle.exportKey("raw", eph.publicKey);
    return ["sello-v1", b64e(epk), b64e(iv), b64e(ct)].join(".");
  }

  $("seal").addEventListener("click", async function () {
    $("err").hidden = true;
    var raw = $("url").value.trim(), q;
    try { q = new URL(raw).searchParams; } catch (e) { q = new URLSearchParams(raw.replace(/^[^?]*\?/, "")); }
    if (q.get("error")) return fail("Google respondió «" + q.get("error") + "». Vuelve a autorizar aceptando todos los permisos.");
    if (!q.get("code")) return fail("No encuentro «code=» en lo pegado. Copia la dirección completa de la barra.");
    if (q.get("state") !== state) return fail("Esta dirección es de otro enlace. Usa el enlace más reciente de la incidencia.");
    try {
      var keep = new URLSearchParams({ state: state, code: q.get("code"), scope: q.get("scope") || "" });
      $("out").value = await seal("?" + keep.toString());
      $("url").value = "";
      $("copy").disabled = false;
    } catch (e) { fail("No se pudo sellar: " + e.message); }
  });

  $("copy").addEventListener("click", async function () {
    try { await navigator.clipboard.writeText($("out").value); }
    catch (e) { $("out").select(); document.execCommand("copy"); }
    $("copied").hidden = false;
  });
})();
