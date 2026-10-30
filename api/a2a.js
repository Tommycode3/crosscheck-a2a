// a2a.js -- the JSON-RPC 2.0 / A2A invocation endpoint.
// Security posture: discovery (the card) is public; INVOCATION is bearer-gated
// by default. Secrets live only in Vercel env vars. No user-supplied URL is
// ever fetched (relay/roundtable only call the fixed room endpoint) -> no SSRF.
const {
  setCors, readJsonBody, task, rpcErr,
  askLLM, callRoomAgent, HOUSE_AGENTS,
} = require("./_shared.js");

const MAX_BODY = 16 * 1024; // 16 KB cap on request text
const MAX_FANOUT = 8;       // never call more than N room agents at once

// Constant-time-ish string compare to avoid trivial timing leaks.
function safeEqual(a, b) {
  a = String(a || ""); b = String(b || "");
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

function authorized(req) {
  // AUTH_REQUIRED defaults to true (secure). Set it to "false" in Vercel
  // env to run an open demo where any stranger's agent can call you.
  const required = (process.env.AUTH_REQUIRED || "true").toLowerCase() !== "false";
  if (!required) return true;
  const token = process.env.AGENT_TOKEN;
  if (!token) return false; // gated but no token configured == closed
  const h = req.headers["authorization"] || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? safeEqual(m[1].trim(), token) : false;
}

function securityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store");
}

module.exports = async (req, res) => {
  // Invocation is server-to-server (agents call it, not browsers), and it is
  // bearer-gated -> do NOT advertise wildcard CORS. (CROSSCHECK flags open CORS
  // on an authenticated endpoint, and it's right: we eat our own dog food.)
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "content-type,authorization");
  securityHeaders(res);
  res.setHeader("content-type", "application/json; charset=utf-8");

  if (req.method === "OPTIONS") { res.status(204).end(); return; }
  if (req.method !== "POST") {
    res.status(405).send(JSON.stringify(rpcErr(null, -32600, "POST a JSON-RPC request")));
    return;
  }

  // Size guard before parsing.
  const len = Number(req.headers["content-length"] || 0);
  if (len > MAX_BODY) {
    res.status(413).send(JSON.stringify(rpcErr(null, -32600, "request too large")));
    return;
  }

  let body;
  try { body = await readJsonBody(req); }
  catch { res.status(400).send(JSON.stringify(rpcErr(null, -32700, "parse error"))); return; }

  const id = body && body.id;

  if (!authorized(req)) {
    // 401 + a typed RPC error: discovery is public, invocation is gated.
    res.status(401).send(JSON.stringify(rpcErr(id, -32001,
      "unauthorized: send Authorization: Bearer <token>. discovery is public, invocation is gated.")));
    return;
  }

  if (!body || body.jsonrpc !== "2.0" || typeof body.method !== "string") {
    res.status(400).send(JSON.stringify(rpcErr(id, -32600, "invalid JSON-RPC envelope")));
    return;
  }
  if (body.method !== "message/send") {
    res.status(404).send(JSON.stringify(rpcErr(id, -32601, "unknown method (only message/send)")));
    return;
  }

  // Extract the message: text part + optional capability metadata.
  const msg = (body.params && body.params.message) || {};
  const parts = Array.isArray(msg.parts) ? msg.parts : [];
  const textPart = parts.find((p) => p && p.kind === "text" && typeof p.text === "string");
  const text = (textPart ? textPart.text : "").slice(0, MAX_BODY);
  const meta = msg.metadata || {};
  const cap = meta.capability || "ask";
  const argsIn = meta.arguments || {};

  try {
    if (cap === "relay") {
      const to = String(argsIn.to || meta.to || "").trim();
      const q = String(argsIn.text || text || "").trim();
      if (!to) { res.status(200).send(JSON.stringify(rpcErr(id, -32602, "relay requires arguments.to (a handle on the wall)"))); return; }
      if (!q)  { res.status(200).send(JSON.stringify(rpcErr(id, -32602, "relay requires text to send"))); return; }
      const reply = await callRoomAgent(to, q);
      res.status(200).send(JSON.stringify(task(id, `[relayed to ${to}]\n${reply}`)));
      return;
    }

    if (cap === "roundtable") {
      const q = String(argsIn.text || text || "").trim();
      if (!q) { res.status(200).send(JSON.stringify(rpcErr(id, -32602, "roundtable requires a question"))); return; }
      let targets = Array.isArray(argsIn.to) && argsIn.to.length ? argsIn.to : HOUSE_AGENTS;
      targets = targets.map(String).slice(0, MAX_FANOUT);
      const settled = await Promise.allSettled(targets.map((t) => callRoomAgent(t, q)));
      const replies = targets.map((t, i) => {
        const r = settled[i];
        return `- ${t}: ${r.status === "fulfilled" ? r.value : "(no reply)"}`;
      });
      const transcript = replies.join("\n");
      const synth = await askLLM(
        `Question put to the room: "${q}"\n\nReplies:\n${transcript}\n\nSynthesize the best single answer in under 80 words. Note any disagreement.`,
        "You are SWITCHBOARD, synthesizing a roundtable of agent replies. Be terse and useful."
      );
      const out = synth
        ? `roundtable (${targets.length} agents):\n${transcript}\n\nsynthesis: ${synth}`
        : `roundtable (${targets.length} agents):\n${transcript}`;
      res.status(200).send(JSON.stringify(task(id, out)));
      return;
    }

    // default: ask
    const q = text.trim();
    if (!q) { res.status(200).send(JSON.stringify(rpcErr(id, -32602, "send a text part with your question"))); return; }
    const answer = await askLLM(q);
    res.status(200).send(JSON.stringify(task(id,
      answer || `switchboard heard: "${q}". (No LLM key set, so this is an echo. Set ANTHROPIC_AUTH_TOKEN in Vercel to make me think.)`)));
  } catch (e) {
    res.status(200).send(JSON.stringify(rpcErr(id, -32000, "internal error handling task")));
  }
};
