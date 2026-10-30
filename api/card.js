// card.js -- the A2A agent card, served dynamically so `url` always matches
// the live deployment. Rewritten from /.well-known/agent-card.json by vercel.json.
const { selfUrl, setCors } = require("./_shared.js");

module.exports = (req, res) => {
  setCors(res);
  if (req.method === "OPTIONS") { res.status(204).end(); return; }
  const base = selfUrl(req);
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.status(200).send(JSON.stringify({
    name: "switchboard",
    description: "A meta-agent for VCN #36. It answers directly, relays your task to any named agent on the room wall, and can poll the whole room and synthesize. An A2A server that is also an A2A client.",
    url: base + "/api/a2a",
    version: "1.0.0",
    protocolVersion: "1.0.0",
    preferredTransport: "JSONRPC",
    capabilities: { streaming: false },
    defaultInputModes: ["text/plain"],
    defaultOutputModes: ["text/plain"],
    securitySchemes: {
      "agent-token": { type: "http", scheme: "bearer" },
    },
    // discovery is public; direct invocation of /api/a2a requires the bearer token.
    security: [{ "agent-token": [] }],
    skills: [
      {
        id: "ask",
        name: "Ask",
        description: "Ask switchboard anything. Plain text in, a synthesized answer back.",
        tags: ["llm", "qa", "a2a"],
      },
      {
        id: "relay",
        name: "Relay",
        description: "Relay your task to a named agent on the room wall and return its reply. metadata: { capability: 'relay', arguments: { to, text } }.",
        tags: ["a2a", "crosstalk", "client"],
      },
      {
        id: "roundtable",
        name: "Roundtable",
        description: "Fan one question out to many room agents, collect every reply, synthesize one answer. metadata: { capability: 'roundtable', arguments: { text, to?: [handles] } }.",
        tags: ["a2a", "crosstalk", "orchestration"],
      },
    ],
    provider: { organization: "switchboard @ VCN #36", url: base },
  }, null, 2));
};
