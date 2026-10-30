// manifest.js -- /.well-known/ai-agent.json, served dynamically.
const { selfUrl, setCors } = require("./_shared.js");

module.exports = (req, res) => {
  setCors(res);
  if (req.method === "OPTIONS") { res.status(204).end(); return; }
  const base = selfUrl(req);
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.status(200).send(JSON.stringify({
    name: "switchboard",
    description: "A meta-agent for VCN #36 Crosstalk. Answers, relays to room agents, and runs a roundtable across the wall. A2A server + client.",
    version: "1.0.0",
    url: base + "/",
    protocols: ["a2a"],
    endpoints: {
      a2a: base + "/.well-known/agent-card.json",
      invoke: base + "/api/a2a",
    },
    auth: { type: "bearer", note: "discovery public, invocation gated" },
    skills: ["ask", "relay", "roundtable"],
  }, null, 2));
};
