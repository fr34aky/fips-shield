# fips-shield documentation

**New here? Start with the [user guide](guide.md).**

### Using it

- **[User guide](guide.md)** — what it protects against, how to install
  and run it (containers or host), every configuration option, and how
  to operate it day to day.
- **[Protecting your own service](protecting-your-service.md)** —
  cookbook for services other than Nostr relays: SSH, databases, HTTP
  APIs and dashboards, Git, several at once, and how to pick limits.
- **[Profile: strfry](../profiles/strfry/README.md)** — Nostr relays,
  including the WebSocket message policy.
- **[Profile: http](../profiles/http/README.md)** — any HTTP app:
  request rate limits, method and path allowlists, body caps.
- **[Profile: tcp](../profiles/tcp/README.md)** — any plain TCP service.
- **[eBPF guard](../guard/README.md)** — optional kernel-level
  enforcement.
- **[Host-mode deployment](../deploy/host/README.md)** — running
  without containers.

### Extending it

- **[Writing a profile](writing-a-profile.md)** — protecting a service
  with protocol-aware rules of its own.
- **[Verdict schema and ban CLI](verdict-schema.md)** — the frozen
  interfaces: what detection modules emit, what enforcement backends
  implement.

### Background

- **[Implementation plan](plan.md)** — how the project was built,
  phase by phase, including the design decisions and their trade-offs.
