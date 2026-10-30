// infra.js -- CROSSCHECK infrastructure / network posture audit for any domain.
// Runs from the cloud: DNS (A/MX/NS/CAA/TXT), TLS cert (issuer/expiry/SAN),
// email security (SPF/DMARC), and security.txt. Real network-layer recon,
// SSRF-guarded to public hostnames only. (Local WiFi/LAN scanning is NOT possible
// from a serverless function -- that needs a local agent on the user's machine.)
const { setCors } = require("./_shared.js");
const crypto = require("crypto");
const dns = require("dns").promises;
const tls = require("tls");

const RS = process.env.RECEIPT_SECRET || process.env.CRON_SECRET || "crosscheck-dev";
function makeReceipt(target, score, gr) {
  const r = { issuer: "crosscheck", target, score, grade: gr, issuedAt: new Date().toISOString(), nonce: crypto.randomBytes(8).toString("hex") };
  const canon = JSON.stringify({ issuer: r.issuer, target: r.target, score: r.score, grade: r.grade, issuedAt: r.issuedAt, nonce: r.nonce });
  r.sig = crypto.createHmac("sha256", RS).update(canon).digest("base64url");
  return r;
}
const grade = (s) => s >= 92 ? "A" : s >= 82 ? "B" : s >= 72 ? "C" : s >= 60 ? "D" : "F";
const F = (level, title, detail, fix) => ({ level, title, detail: detail || "", fix: fix || "" });

function publicHost(h) {
  h = (h || "").toLowerCase().trim();
  if (h.includes("://")) { try { h = new URL(h).hostname; } catch {} }
  if (!h || h === "localhost" || h.endsWith(".local") || h.endsWith(".internal")) return null;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
    const p = h.split(".").map(Number);
    if ([10, 127, 0].includes(p[0]) || (p[0] === 192 && p[1] === 168) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 169 && p[1] === 254)) return null;
  }
  return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(h) ? h : null;
}

function getCert(host) {
  return new Promise((resolve) => {
    let done = false; const fin = (v) => { if (!done) { done = true; resolve(v); } };
    try {
      const s = tls.connect({ host, port: 443, servername: host, timeout: 8000, rejectUnauthorized: false }, () => {
        const c = s.getPeerCertificate(); const authorized = s.authorized; const proto = s.getProtocol(); s.end(); fin({ c, authorized, proto });
      });
      s.on("error", () => fin(null));
      s.on("timeout", () => { s.destroy(); fin(null); });
    } catch { fin(null); }
  });
}
const tryDns = async (fn) => { try { return await fn(); } catch { return null; } };

async function auditDomain(input) {
  const host = publicHost(input);
  if (!host) return { target: input, score: 0, grade: "F", findings: [F("fail", "Invalid / private host", "Provide a public domain (SSRF guard).")], counts: {}, recommendations: [], receipt: makeReceipt(String(input), 0, "F") };

  const findings = []; let score = 100; const metrics = { host };

  // DNS
  const a = await tryDns(() => dns.resolve4(host));
  if (a) { findings.push(F("pass", "DNS resolves", `${a.length} A record(s): ${a.slice(0, 3).join(", ")}.`)); metrics.a = a; }
  else { findings.push(F("fail", "No A record", "Hostname does not resolve to IPv4.")); score -= 20; }
  const ns = await tryDns(() => dns.resolveNs(host));
  if (ns) findings.push(F("info", "Nameservers", ns.slice(0, 3).join(", ")));
  const caa = await tryDns(() => dns.resolveCaa(host));
  if (caa && caa.length) findings.push(F("pass", "CAA set", "Certificate issuance is restricted by CAA."));
  else { findings.push(F("warn", "No CAA record", "Any CA can issue certs for this domain.", "Add a CAA record pinning your CA.")); score -= 4; }

  // TLS certificate
  const tlsRes = await getCert(host);
  if (tlsRes && tlsRes.c && tlsRes.c.valid_to) {
    const days = Math.round((Date.parse(tlsRes.c.valid_to) - Date.now()) / 8.64e7);
    const issuer = (tlsRes.c.issuer && (tlsRes.c.issuer.O || tlsRes.c.issuer.CN)) || "?";
    metrics.tls = { issuer, daysLeft: days, validTo: tlsRes.c.valid_to };
    if (!tlsRes.authorized) { findings.push(F("fail", "TLS chain invalid", "Certificate did not validate against trusted roots.", "Fix the cert chain / install intermediates.")); score -= 18; }
    else if (days < 0) { findings.push(F("fail", "TLS cert EXPIRED", `Expired ${-days} days ago.`, "Renew immediately.")); score -= 30; }
    else if (days < 14) { findings.push(F("warn", "TLS cert expiring soon", `${days} days left (issuer ${issuer}).`, "Renew / check auto-renewal.")); score -= 8; }
    else findings.push(F("pass", "Valid TLS cert", `${days} days left, issued by ${issuer}.`));
    const proto = tlsRes.proto || "";
    if (/TLSv1(\.1)?$/.test(proto)) { findings.push(F("fail", "Deprecated TLS protocol", `Negotiated ${proto} -- TLS 1.0/1.1 are deprecated and insecure.`, "Require TLS 1.2+ at the server/CDN.")); score -= 16; }
    else if (proto) findings.push(F("pass", "Modern TLS", `Negotiated ${proto}.`));
  } else { findings.push(F("warn", "TLS not inspected", "Could not complete a TLS handshake on :443.")); score -= 6; }

  // email security (SPF / DMARC)
  const txt = await tryDns(() => dns.resolveTxt(host));
  const flat = (txt || []).map((r) => r.join("")).join(" | ");
  if (/v=spf1/i.test(flat)) findings.push(F("pass", "SPF present", "Sender Policy Framework record found."));
  else { findings.push(F("warn", "No SPF", "No v=spf1 TXT record -- domain is easier to spoof in email.", "Publish an SPF record.")); score -= 6; }
  const dmarc = await tryDns(() => dns.resolveTxt("_dmarc." + host));
  const dflat = (dmarc || []).map((r) => r.join("")).join(" ");
  if (/v=DMARC1/i.test(dflat)) findings.push(F("pass", "DMARC present", "DMARC policy found."));
  else { findings.push(F("warn", "No DMARC", "No _dmarc record -- spoofed mail won't be rejected/reported.", "Publish a DMARC policy (start p=none).")); score -= 6; }

  // security.txt
  try {
    const r = await fetch("https://" + host + "/.well-known/security.txt", { signal: AbortSignal.timeout(6000) });
    if (r.ok) findings.push(F("pass", "security.txt published", "Has a /.well-known/security.txt contact."));
    else throw 0;
  } catch { findings.push(F("info", "No security.txt", "No /.well-known/security.txt for vuln reporting.", "Add a security.txt with a contact.")); }

  score = Math.max(0, Math.min(100, Math.round(score)));
  const counts = findings.reduce((acc, f) => (acc[f.level] = (acc[f.level] || 0) + 1, acc), {});
  const gr = grade(score);
  const recommendations = findings.filter((f) => (f.level === "fail" || f.level === "warn") && f.fix).map((f) => ({ priority: f.level === "fail" ? "high" : "medium", issue: f.title, fix: f.fix }));
  return { target: host, mode: "infra", score, grade: gr, counts, findings, recommendations, metrics, receipt: makeReceipt(host, score, gr) };
}

module.exports = async (req, res) => {
  setCors(res);
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  if (req.method === "OPTIONS") { res.status(204).end(); return; }
  let body = {};
  if (req.method === "POST") { try { const c = []; for await (const x of req) c.push(x); body = JSON.parse(Buffer.concat(c).toString("utf8") || "{}"); } catch {} }
  const dom = (req.query && (req.query.domain || req.query.host)) || body.domain;
  if (!dom) { res.status(400).send(JSON.stringify({ error: "provide ?domain=<host>" })); return; }
  try { res.status(200).send(JSON.stringify(await auditDomain(String(dom)), null, 2)); }
  catch { res.status(200).send(JSON.stringify({ error: "infra scan failed" })); }
};
