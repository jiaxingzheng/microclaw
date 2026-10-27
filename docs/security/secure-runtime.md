# Secure Runtime

MicroClaw applies security at the shared runtime boundaries so main-agent,
subagent, channel, MCP, and dynamic-plugin calls cannot bypass a policy by
choosing a different adapter.

## 1. Global and scoped tool policy

The global tool policy is the outer boundary. It is evaluated at the single
registry choke point (`ToolRegistry::execute_with_auth`), so main-agent,
sub-agent, scheduler and plugin calls are all covered, and tools it blocks
are also left out of the catalog sent to the model
(`ToolRegistry::definitions_for`). Scoped grants add least-privilege rules
for a chat, channel, or runtime principal:

```yaml
tool_policy:
  mode: block
  allow_tools: [read_file, glob, grep, web_*]   # allowlist (empty = no restriction)
  deny_tools: [bash]                            # always blocked, wins over allow
  max_risk: medium                              # risk ceiling, also for allow-listed tools

  grants_mode: block
  control_chat_bypass: true
  grants:
    - chat_id: 12345
      principal: main
      allow_tools: ["*"]
      deny_tools: [bash]
      max_risk: medium

    - channel: slack
      principal: "subagent:*"
      allow_tools: [read_file, glob, grep, web_search]
      deny_tools: [send_message, bash]
      max_risk: medium
```

Global rule behavior (`mode: warn | block`; `off` evaluates nothing):

- Every rule only removes tools; none widens. Evaluation order is
  `deny_tools`, then `allow_tools`, then `max_risk`.
- `deny_tools` always blocks, even for a tool that is also in `allow_tools`.
- A non-empty `allow_tools` is an allowlist: every tool not listed is a
  violation. An empty list means "no allowlist", not "allow nothing".
- `max_risk` blocks tools above the tier even when they are allow-listed. To
  permit a high-risk tool, raise or unset `max_risk`.
- All tool lists, global and per grant, accept `*` and trailing wildcards
  such as `mcp_*`.
- `mode: block` with no `allow_tools`, `deny_tools` or `max_risk` restricts
  nothing. `microclaw doctor` (`security.tool_policy`) and
  `microclaw config check` warn about that configuration.
- Under `block`, blocked tools are not offered to the model at all; under
  `warn`, every tool stays in the catalog and violations are audited.

Before 0.11.1 the global `allow_tools` was an *exemption* list (it lifted
`deny_tools` / `max_risk` for the listed tools) and global lists were
exact-match only, so `allow_tools: [read_file]` on its own restricted
nothing. See the 0.11.1 changelog entry.

Principals currently include:

- `main`;
- `scheduler`;
- `channel:<name>` for direct channel tool calls;
- `subagent:<run_id>`;
- future TypeScript plugins: `plugin:<plugin_id>`.

Grant rule behavior:

- A global block always wins; a scoped grant cannot weaken it.
- `grants_mode: off` preserves historical behavior.
- No matching rule is a violation when grants are active.
- All matching rules are combined conservatively: any deny or exceeded risk
  blocks; at least one matching allow is required.
- `control_chat_bypass` bypasses only scoped grants, never the global policy.
- Warn/block decisions include principal identity in the audit actor.

Start with `warn`, review the audit trail, then switch to `block`.

## 2. Outbound destination policy

```yaml
egress_policy:
  mode: block
  allow_hosts:
    - api.openai.com
    - "*.example.com"
  deny_hosts: []
  block_private_ips: true
```

When active, the policy:

- validates explicit LLM, embedding, media, SearXNG, A2A, active ClawHub, and
  enabled-channel HTTP(S) endpoints during config load;
- scans tool input, including URLs embedded in shell text, at the shared
  registry boundary;
- supports exact hosts and `*.example.com` patterns;
- rejects non-HTTP schemes;
- can reject loopback, private, link-local, CGNAT, metadata, multicast, and
  unresolved destinations;
- writes warnings and blocks to audit kind `egress_policy`.

When `allow_hosts` is non-empty, list every enabled service that MicroClaw may
contact. For example, installations that keep ClawHub agent tools enabled must
allow the configured ClawHub registry host. Text that merely contains a URL,
such as a SOUL file path or prompt, is not treated as an outbound endpoint.

HTTP clients must continue to apply the existing redirect SSRF policy on every
hop. The input scanner cannot prove what an arbitrary shell program will do:
a command can construct a hostname dynamically or use a non-HTTP protocol.
For command-level network isolation, use the container boundary below.

## 3. Container and credential boundary

Recommended production baseline:

```yaml
sandbox:
  mode: all
  backend: auto
  require_runtime: true
  security_profile: hardened
  no_network: true
  credential_env_allowlist: []
```

With `require_runtime: true`, a missing container runtime fails closed instead
of falling back to host execution. `hardened` drops Linux capabilities and
disables privilege escalation. `no_network` enforces command egress at the
container boundary.

Dotenv files used by skills/tools are parsed on the host and are never supplied
wholesale with container `--env-file`. Variables whose names look like API
keys, access keys, private keys, secrets, tokens, passwords, credentials, or
authorization are withheld by default. An exact, case-insensitive name in
`credential_env_allowlist` is required to pass one.

The allowlist is an escape hatch. Prefer mediated host APIs and secret
references for future TypeScript plugins so the child process never receives
unrelated credentials.

## 3b. Structured high-risk approvals

When a high-risk tool call pauses for confirmation (web and control chats, or
any chat hitting the bash dangerous-pattern / sandboxed-peer gates), the
prompt is a numbered option card:

1. **Approve once** — reply `1` / `approve` / `批准` (the historical flow).
2. **Always allow this tool in this chat** — reply `2` / `always` / `总是`.
   Records a standing per-chat allowance, sealed into the audit chain and
   consulted at the registry choke point. It satisfies only the confirmation
   gate: tool policy, egress policy, and in-tool gates (e.g. bash dangerous
   patterns) still run. List or revoke with `/approvals` and
   `/approvals clear`.
3. **Deny** — reply `3` / `deny`, or send any other instruction.

Web clients additionally receive a structured `approval_required` stream
event (approval id, tool, preview, options) so they can render buttons
instead of parsing text. Prompt language follows `user_message_language`
(en / zh / bilingual); reply keywords are recognized in both languages
regardless.

Optionally, `aux_models.approval_reviewer` names a model that annotates each
approval prompt with a one-line advisory verdict (SAFE / CAUTION / DANGEROUS
+ reason). It is off unless set — there is deliberately no fallback to the
main model — and it is advisory only: it never approves, denies, or alters
the gate.

## 4. Operator visibility

- `microclaw doctor` reports whether scoped grants and egress policy are
  enabled and summarizes the sandbox credential boundary.
- `microclaw doctor sandbox` includes the same policy checks plus container,
  image, and mount diagnostics.
- Web config self-check warns about disabled grants/egress, sandbox networking,
  and missing runtime isolation.
- Web Governance can edit scoped grant JSON, egress hosts/mode, and the exact
  sandbox credential allowlist.

All web mutations require admin scope and retain the existing safe config-save
and restart-to-apply behavior.

## Migration

New enforcement modes default to `off` for backward compatibility. Credential
filtering is active whenever execution uses a real container; installations
that intentionally pass a credential into sandboxed commands must add its exact
variable name.

Suggested rollout:

1. Keep high-risk confirmation enabled.
2. Enable the hardened, no-network sandbox with `require_runtime: true`.
3. Set capability grants and egress policy to `warn`.
4. Exercise normal workloads and review governance/audit output.
5. Add only necessary grants and hosts.
6. Switch both policies to `block`.
