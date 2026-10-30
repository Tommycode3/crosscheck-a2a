// verify.js -- verify a CROSSCHECK conformance receipt (the trust layer).
// POST { receipt } -> { valid, reason }. Anyone can check an attestation without
// trusting the bearer; only CROSSCHECK can mint one (HMAC over canonical fields).
const { setCors } = require("./_shared.js");
const crypto = require("crypto");

const RECEIPT_SECRET = process.env.RECEIPT_SECRET || process.env.CRON_SECRET || "crosscheck-dev";

function expected(r) {
  const canon = JSON.stringify({ issuer: r.issuer, target: r.target, score: r.score, grade: r.grade, issuedAt: r.issuedAt, nonce: r.nonce });
  return crypto.createHmac("sha256", RECEIPT_SECRET).update(canon).digest("base64url");
}

module.exports = async (req, res) => {
  setCors(res);
  res.setHeader("content-type", "application/json; charset=utf-8");
  if (req.method === "OPTIONS") { res.status(204).end(); return; }

  let body = {};
  if (req.method === "POST") {
    try { const c = []; for await (const x of req) c.push(x); body = JSON.parse(Buffer.concat(c).toString("utf8") || "{}"); } catch {}
  } else if (req.query && req.query.r) {
    try { body.receipt = JSON.parse(Buffer.from(req.query.r, "base64url").toString("utf8")); } catch {}
  }
  const r = body.receipt || body;
  if (!r || !r.sig || !r.issuer) { res.status(400).send(JSON.stringify({ valid: false, reason: "no receipt" })); return; }

  const want = expected(r);
  const ok = r.sig.length === want.length && crypto.timingSafeEqual(Buffer.from(r.sig), Buffer.from(want));
  const ageMs = r.issuedAt ? (Date.now() - Date.parse(r.issuedAt)) : null;
  res.status(200).send(JSON.stringify({
    valid: ok,
    reason: ok ? "signature valid -- minted by CROSSCHECK" : "signature mismatch -- forged or altered",
    attests: ok ? { target: r.target, score: r.score, grade: r.grade, issuedAt: r.issuedAt, ageHours: ageMs == null ? null : Math.round(ageMs / 3.6e5 * 10) / 10 } : null,
  }, null, 2));
};
