# crosscheck-a2a

CROSSCHECK audits [A2A (Agent2Agent)](https://a2a-protocol.org) agents. Give it the
URL of an agent card and it fetches the card, calls the endpoint the card advertises,
runs a few non-destructive security probes and returns a graded report with fixes and
an HMAC-signed receipt. It also has a passive observability view for a live room of
agents. It was written in one night at Vibe Coding Nights #36 ("Crosstalk") and runs
as Vercel functions with no npm dependencies.

Live at <https://crosstalk-agent.vercel.app> (dashboard at `/probe`, room graph at `/map`).

## Usage

```sh
curl "https://crosstalk-agent.vercel.app/api/scan?url=<agent-card-url>&summary=1"
curl "https://crosstalk-agent.vercel.app/api/scan?mode=room"
curl "https://crosstalk-agent.vercel.app/api/infra?domain=example.com"
```

| Path | Auth | Purpose |
|---|---|---|
| `/.well-known/agent-card.json` | public | switchboard's A2A card, generated per request so `url` matches the deployment |
| `/api/scan?url=<card>[&summary=1]` | public, SSRF-guarded | audit one agent card |
| `/api/scan?probe=<url>` | public, SSRF-guarded | HTTPS security-header probe |
| `/api/scan?mode=room` | public | passive room report and graph (reads the feed, sends nothing) |
| `/api/infra?domain=<host>` | public, host-guarded | DNS, TLS and email-security posture |
| `/api/verify` | public | verify a receipt (POST `{receipt}` or `?r=<base64url>`) |
| `/api/a2a` | bearer `AGENT_TOKEN` | switchboard's JSON-RPC `message/send` (`ask`, `relay`, `roundtable`) |
| `/api/worker` | bearer `CRON_SECRET` | drains switchboard's inbox on the room registry |

To deploy your own copy, run `vercel --prod`. `RECEIPT_SECRET` is the HMAC key for
receipts, `AGENT_TOKEN` gates `message/send` (`AUTH_REQUIRED=false` opens it, demo
only) and `CRON_SECRET` gates the worker and doubles as the fallback receipt key.
`ANTHROPIC_AUTH_TOKEN` or `ANTHROPIC_API_KEY` is optional and enables LLM summaries;
`ANTHROPIC_BASE_URL` and `ANTHROPIC_MODEL` point at any Anthropic-compatible
`/v1/messages` gateway (GLM-4.6 at the event). `AGENT_HANDLE` and `SELF_BASE` set
switchboard's handle and public URL, and `PROACTIVE=on` enables outbound messages.

## Scoring

`api/scan.js` fetches the card, sends a `message/send` conformance probe to its `url`,
hits each `skills[].endpoint`, then runs deep probes: an unknown method, a prompt
injection, an auth fuzz, `tasks/list` and a malformed JSON body. Each check emits a
`pass`, `info`, `warn` or `fail` finding; warnings and failures carry a penalty $p_i$
and the deep probes add $\Delta \le 0$:

$$
S = \operatorname{clamp}_{[0,\,100]}\!\left(\operatorname{round}\!\left(100 - \sum_i p_i + \Delta\right)\right)
$$

Grades are A for $S \ge 92$, B for $\ge 82$, C for $\ge 72$, D for $\ge 60$, F
otherwise. The web probe, the infra audit and the local script use the same thresholds.

| Check | Penalty |
|---|---|
| card not HTTP 200 / not JSON / unreachable | 30 / 40 / 45 (last two stop the audit) |
| card not at `/.well-known/agent-card.json` | 6 |
| missing `name`, `description` or `url` | 14 each |
| no `securitySchemes` / scheme declared but `security[]` empty | 10 / 6 |
| `url` answers `message/send` with non-JSON, or is unreachable | 22 |
| JSON that is neither a Task nor a JSON-RPC error | 12 |
| skill endpoint returns 404 or 5xx / unreachable | 14 / 6 each |
| deep: unknown method crashes (5xx or HTML) | 12 |
| deep: error body leaks stack traces or paths | 14 |
| deep: `Access-Control-Allow-Origin: *` on a gated endpoint | 6 |
| deep: prompt injection leaks secret-shaped strings / leaks instructions | 40 / 10 |
| deep: empty, `null` or wrong bearer token accepted | 40 |
| deep: `tasks/list` readable without auth | 8 |
| deep: malformed JSON body gives a 5xx or a leak | 6 |

The injection probe only runs when the endpoint returns a Task without credentials,
and the auth matrix only runs when the card declares `security[]`. Secrets are
detected by regex (`sk-…`, `AKIA…`, `ghp_…`, `xox?-…`, PEM private keys).

Every report carries a receipt $\sigma = \operatorname{base64url}(\operatorname{HMAC\text{-}SHA256}_K(\mathrm{JSON}(\text{issuer}, \text{target}, \text{score}, \text{grade}, \text{issuedAt}, \text{nonce})))$
with $K$ = `RECEIPT_SECRET`. `/api/verify` recomputes it and compares with
`crypto.timingSafeEqual`. Being a symmetric MAC, only this deployment can verify its
own receipts; a public-key signature would be the next step.

At the event the auditor graded the workshop's own deck D / 68 (its card's `url` was
not a JSON-RPC route and `message/send` returned 405 HTML), a production agent B / 90
(conformant, no security scheme declared) and switchboard A / 94 (empty `security[]`
in the public demo configuration). These are point-in-time results and cannot be
reproduced from this repo.

## Room and switchboard

`?mode=room` reads the room registry's `/feed` and sends no traffic to any agent. For
an agent $a$ with $r_a$ calls received and $c_a$ completions, $\rho_a =
\operatorname{round}(100 \cdot c_a / r_a)$, and $a$ is a ghost if $r_a \ge 2$ and
$\rho_a < 20$. `/map` bins $\rho_a$ at 80 / 50 / 20 / >0 and the report lists the
busiest nodes and the top caller to callee edges.

switchboard is the project's own A2A agent and the reference the auditor is checked
against. `/api/a2a` is closed unless `AGENT_TOKEN` is set (`AUTH_REQUIRED` defaults to
true), bodies are capped at 16 KB and fan-out at 8 agents, and relay and roundtable
only ever call the fixed room endpoint. `/api/worker` answers text commands from the
inbox: `audit <card-url>`, `webscan <url>`, `infra <domain>`, `meet <what you're
building>`, `who`, `leaderboard`, `relay <agent>: <msg>`, `roundtable: <q>`,
`card <desc>`, or a free-form question. Its proactive behaviour (greeting arrivals,
poking house bots) runs only with `PROACTIVE=on`.

`public/crosscheck-local.sh` covers what a serverless function cannot see, the machine
it runs on: Wi-Fi encryption (it prints the SSID), firewall, SSH, Screen Sharing and
SMB, sockets listening on all interfaces, DNS resolver, ARP cache size and SIP on
macOS, a smaller set via `nmcli`, `ss` and `ufw` on Linux. It is read-only, needs no
sudo, makes no network calls and prints to the terminal only. Read it before you run it.

## Limitations

- Hackathon code, written in one night. No tests.
- The room registry URL and house-agent list in `api/_shared.js` are specific to the event.
- The SSRF guard checks the hostname string only. It does not resolve DNS, so a public
  name pointing at a private address gets through.
- With neither `RECEIPT_SECRET` nor `CRON_SECRET` set, receipts use a hard-coded
  development key and are forgeable.
- The worker compares `CRON_SECRET` with `===` and also accepts it as `?key=`.
- Only audit agents you own or are authorised to test. The probes are non-destructive
  but they do send a prompt injection and malformed tokens.

## License

MIT. See [LICENSE](LICENSE).
