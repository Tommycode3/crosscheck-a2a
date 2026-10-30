// _shared.js -- helpers shared by the A2A routes. ASCII-only, zero deps.

// The Immersive Commons room registry / A2A endpoint for VCN #36.
const ROOM_BASE = "https://www.immersivecommons.com/api/workshop/crosstalk";

// House agents that live on the wall (deck-listed defaults for roundtable).
const HOUSE_AGENTS = [
  "greeter-prime",
  "haiku-bot",
  "dice-oracle",
  "echo-revere",
  "fortune-teller",
  "registry-cat",
];

// The handle this agent uses when it acts as a CLIENT calling the room.
const MY_HANDLE = process.env.AGENT_HANDLE || "switchboard";

function selfUrl(req) {
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  const proto = req.headers["x-forwarded-proto"] || "https";
  return `${proto}://${host}`;
}

async function readJsonBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return {}; }
}

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "content-type,authorization");
}

// fetch with a timeout so a slow/dead peer never hangs the function.
async function fetchT(url, opts = {}, ms = 12000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

// Build a completed A2A Task object wrapping a text answer.
function task(id, text, extraStatus = {}) {
  return {
    jsonrpc: "2.0",
    id: id ?? null,
    result: {
      kind: "task",
      id: "task-" + Math.abs(hash(text + String(id))).toString(36),
      status: { state: "completed", ...extraStatus },
      artifacts: [
        { parts: [{ kind: "text", text: String(text) }] },
      ],
    },
  };
}

function rpcErr(id, code, message) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

function hash(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) { h = (h * 31 + s.charCodeAt(i)) | 0; }
  return h;
}

// ---- LLM call (optional). Anthropic-style /v1/messages. ----
// Works with a real Anthropic key OR the workshop Z.AI / GLM gateway,
// just by setting ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN + ANTHROPIC_MODEL.
async function askLLM(prompt, system, timeoutMs = 20000) {
  const base = process.env.ANTHROPIC_BASE_URL || "https://api.anthropic.com";
  const token = process.env.ANTHROPIC_AUTH_TOKEN || process.env.ANTHROPIC_API_KEY;
  const model = process.env.ANTHROPIC_MODEL || "claude-haiku-4-5-20251001";
  if (!token) return null; // graceful: caller falls back to a canned reply
  const r = await fetchT(base.replace(/\/$/, "") + "/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": token,
      "authorization": "Bearer " + token,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model,
      max_tokens: 600,
      system: system || "You are SWITCHBOARD, a terse, witty A2A agent at a builder night. Answer in under 80 words.",
      messages: [{ role: "user", content: prompt }],
    }),
  }, timeoutMs);
  if (!r.ok) return null;
  const data = await r.json().catch(() => null);
  const out = data && data.content && data.content.map((b) => b.text || "").join("").trim();
  return out || null;
}

// ---- Call another agent in the room over A2A. ----
async function callRoomAgent(to, text) {
  const body = {
    jsonrpc: "2.0",
    id: Math.abs(hash(to + text)),
    method: "message/send",
    params: {
      message: {
        role: "user",
        parts: [{ kind: "text", text }],
        metadata: { name: MY_HANDLE, to },
      },
    },
  };
  const r = await fetchT(ROOM_BASE + "/a2a", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await r.json().catch(() => null);
  return extractText(data) || `(no readable reply from ${to})`;
}

// Read the live wall: agents on it + recent wire events.
async function getFeed() {
  try {
    const r = await fetchT(ROOM_BASE + "/feed", {}, 9000);
    const d = await r.json().catch(() => null);
    if (!d) return { agents: [], events: [], cursor: 0 };
    return { agents: d.agents || [], events: d.events || [], cursor: d.cursor || 0 };
  } catch { return { agents: [], events: [], cursor: 0 }; }
}

// Send a task TO another agent on the wall (proactive, fire-and-read).
async function sendTo(to, text) {
  try {
    const r = await fetchT(ROOM_BASE + "/a2a", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0", id: Math.abs(hash(to + text)) % 100000,
        method: "message/send",
        params: { message: {
          role: "agent",
          parts: [{ kind: "text", text: String(text).slice(0, 600) }],
          metadata: { name: MY_HANDLE, to },
        } },
      }),
    });
    const d = await r.json().catch(() => null);
    return extractText(d);
  } catch { return null; }
}

// Pull the first text artifact/part out of an A2A response.
function extractText(data) {
  if (!data) return null;
  const res = data.result || data;
  const arts = res && (res.artifacts || (res.status && res.status.message && [res.status.message]));
  if (Array.isArray(arts)) {
    for (const a of arts) {
      const parts = a.parts || (a.message && a.message.parts);
      if (Array.isArray(parts)) {
        for (const p of parts) if (p && p.text) return p.text;
      }
    }
  }
  if (res && res.message && Array.isArray(res.message.parts)) {
    for (const p of res.message.parts) if (p && p.text) return p.text;
  }
  if (data.error) return `error ${data.error.code}: ${data.error.message}`;
  return null;
}

module.exports = {
  ROOM_BASE, HOUSE_AGENTS, MY_HANDLE,
  selfUrl, readJsonBody, setCors, fetchT,
  task, rpcErr, askLLM, callRoomAgent, extractText,
  getFeed, sendTo,
};
