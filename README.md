# vaultlet

A gRPC control plane for secrets you already store somewhere else.

vaultlet does not store secrets. It sits in front of a backend you already run —
Bitwarden Secrets Manager, AWS Secrets Manager, or a local encrypted file — and
gives you three things that backend does not:

1. **One access model.** A GitLab CI job authenticates with its OIDC token; a
   workload authenticates with mTLS. Policy is expressed over pipeline claims and
   namespaces, not over per-backend IAM dialects.
2. **Push, not poll.** Clients open a `Watch` stream and receive new values within
   seconds of a rotation. No restarts, no polling storms.
3. **One audit log.** Every read, denial and change, in one place, regardless of
   which backend served it.

Read-mostly by design. Secrets are created and edited in the backend's own UI.

---

## Status

Pre-v0.1. See [Roadmap](#roadmap) for what is built and what is not.

---

## Quick start

```bash
# Run against a local file backend — no cloud account needed
go run ./cmd/vaultlet --config ./examples/dev.yaml

# In another terminal
go run ./cmd/vaultlet-cli get dev/local/DB_URL --server localhost:8443
go run ./cmd/vaultlet-cli watch dev/local --server localhost:8443
```

Change a value in the file store while `watch` is running; the event arrives on
the open stream.

---

## Architecture

Ports and adapters. The core (`internal/domain`, `internal/app`) has no knowledge
of gRPC, Bitwarden, AWS, or configuration formats. Everything external is an
adapter behind an interface.

```
                    DRIVING ADAPTERS
              ┌───────────┬───────────┐
              │   gRPC    │    CLI    │
              └─────┬─────┴─────┬─────┘
                    │           │
                 ┌──▼───────────▼──┐
                 │   internal/app  │   use cases
                 │  ─────────────  │
                 │ internal/domain │   entities, policy
                 └──┬───────────┬──┘
                    │           │
              ┌─────▼─────┬─────▼──────┬──────────┐
              │ SecretStore│ AuthProvider│ AuditSink│   PORTS
              └─────┬─────┴─────┬──────┴────┬─────┘
                    │           │           │
              ┌─────▼─────┬─────▼──────┬────▼─────┐
              │ bitwarden │   oidc     │ logaudit │   DRIVEN ADAPTERS
              │ awssm     │            │ pgaudit  │
              │ file      │            │          │
              └───────────┴────────────┴──────────┘
```

**The two rules, enforced by `depguard` in CI:**

- `internal/domain` and `internal/app` never import `internal/adapters/*`.
- No adapter imports another adapter.

`cmd/vaultlet/main.go` is the composition root — the only file allowed to know
which concrete adapters exist.

### Layout

```
vaultlet/
├── api/proto/                    # .proto definitions + generated code
├── cmd/
│   ├── vaultlet/                 # server binary; wiring lives here
│   └── vaultlet-cli/             # client binary
├── internal/
│   ├── domain/                   # Key, Secret, Version, Principal, Policy, Event
│   ├── ports/                    # SecretStore, Watcher, AuthProvider, AuditSink
│   ├── app/                      # use cases: Get, List, WatchNamespace, Authenticate
│   ├── config/                   # koanf loading; aggregates adapter Configs
│   └── adapters/
│       ├── grpc/                 # driving: proto ↔ domain mapping, interceptors
│       ├── cli/                  # driving
│       ├── file/                 # driven: SecretStore over encrypted local file
│       ├── bitwarden/            # driven: Bitwarden Secrets Manager
│       ├── awssm/                # driven: AWS Secrets Manager
│       ├── watch/                # decorator: polling fallback for non-Watchers
│       ├── oidc/                 # driven: JWT verification against a JWKS
│       └── logaudit/             # driven: audit to structured logs
├── test/conformance/             # one suite every SecretStore must pass
├── docs/adr/                     # architecture decision records
└── examples/                     # sample configs
```

---

## Core concepts

### Keys and namespaces

A key is `namespace/name`, e.g. `payments/prod/DB_URL`.

- Namespace segments: lowercase alphanumeric and hyphens, max 8 deep.
- Names: alphanumeric plus `_ . -`.
- Patterns: `payments/*` matches one level; `payments/**` matches any depth.

Construct keys only via `domain.ParseKey` — the fields are unexported, so an
invalid `Key` cannot exist anywhere downstream.

### Versions

`domain.Version` is an **opaque** string. Backends map their own notion into it
(AWS `VersionId`, Bitwarden `revisionDate`, a counter in the file store).
Versions are comparable for equality only — never ordered. Sort by
`SecretMeta.CreatedAt` if you need chronology.

### Principals and policy

A `Principal` is `{Type, Subject, Claims}`. Types are `CIJob`, `Workload`, `User`.
Claims come from the auth adapter (e.g. GitLab's `project_path`, `ref`,
`environment`) and are never parsed in the domain.

Policy rules match claims to namespace patterns:

```yaml
rules:
  - match:
      project_path: eightmile/payments
      ref: main
    actions: [read]
    namespaces: [payments/prod/**]

  - match:
      project_path: eightmile/payments
    actions: [read]
    namespaces: [payments/staging/**]
```

`Policy.Allows(principal, action, key)` is pure and has no I/O. It is the most
heavily tested function in the codebase.

### Watch

`Watch` is a server-streaming RPC: the client subscribes to a namespace once and
the server pushes `SecretEvent` messages as things change.

`Watch` is a method on `ports.SecretStore`, so every backend implements it.
None of the current backends can notify natively, so each one's `Watch` calls
`watch.Poll` (`internal/adapters/driven/watch`), which takes a snapshot,
replays it as `Added` events, sends `InSync`, then polls `List` on the
configured interval and emits `Added`, `Updated` and `Deleted` as versions
change. A failed poll is logged and skipped; the stream stays open. A backend
that gains native notification (AWS via EventBridge) can implement `Watch`
directly without touching the poller.

Subscribing requires both `list` and `watch` on a namespace overlapping the
request, and each event is filtered against the subscriber's `list` and
`watch` rules before it is sent.

---

## Configuration

Precedence, lowest to highest: **defaults → YAML file → environment variables →
flags.**

Config file search order (first hit wins):

1. `--config <path>`
2. `$VAULTLET_CONFIG`
3. `./vaultlet.yaml`
4. `/etc/vaultlet/config.yaml`

A missing config file is **not** an error — the service can be configured
entirely by environment, which is how it runs in Swarm. A config file passed
explicitly via `--config` that does not exist **is** a fatal error.

```yaml
# examples/dev.yaml
listen: ':8443'
backend: file
log_level: debug

file:
  path: ./.vaultlet/dev.db

poll_interval: 30s
```

```yaml
# examples/bitwarden.yaml
listen: ':8443'
backend: bitwarden

bitwarden:
  api_url: https://bw.example.internal/api
  identity_url: https://bw.example.internal/identity
  projectid: 3f9c1a7e-...
  # access token is read from BW_ACCESS_TOKEN — never put it in this file

oidc:
  issuer: https://gitlab.com
  audience: vaultlet
```

Environment overrides use `VAULTLET_` with `__` as the section separator:

```bash
VAULTLET_BACKEND=bitwarden
VAULTLET_BITWARDEN__PROJECTID=3f9c1a7e-...
BW_ACCESS_TOKEN=...            # secret, deliberately outside the VAULTLET_ namespace
```

`Config.Validate()` runs against the merged result, so a bad env var fails at
startup rather than on the first request.

---

## Backends

| Backend     | Reads | Writes           | Native watch | Notes                                                                                         |
| ----------- | ----- | ---------------- | ------------ | --------------------------------------------------------------------------------------------- |
| `bitwarden` | ✅    | `allow_writes`   | ❌ (polled)  | Bitwarden Secrets Manager, scoped to one project.                                             |
| `azure`     | ✅    | `allow_writes`   | ❌ (polled)  | Azure Key Vault secrets. Keys are encoded into vault names; see below.                        |
| `gcp`       | ✅    | `allow_writes`   | ❌ (polled)  | Google Cloud Secret Manager. One secret per key, one version per Put; see below.              |
| `aws`       | ✅    | ❌               | planned      | AWS Secrets Manager. Not started.                                                             |

### Azure Key Vault

Key Vault names allow only `[0-9a-zA-Z-]` and compare case-insensitively, so
a key such as `payments/prod/DB_URL` is stored under an escaped name
(`payments-1prod-1-d-b-2-u-r-l`; `-` escapes `-`, `/`, `_`, `.` and uppercase).
The canonical key is also written to the `vaultlet-key` tag so the portal
stays readable. Secrets created by hand that do not follow the encoding are
ignored by `List` and `Watch`. Namespaces are filtered client-side from a
full listing of the vault.

Delete is a Key Vault soft delete: the name is unusable until the secret is
purged or the retention period ends. `purge_on_delete: true` purges right
after deleting, which needs the purge permission and a vault without purge
protection. Versions are the secret's `Updated` timestamp, not Key Vault's
own version identifier, because the listing endpoint does not return it.

Authentication uses the SDK's default credential chain unless `tenant_id`,
`client_id` and `client_secret` are all set, in which case that service
principal is used. The identity needs the Key Vault Secrets User role for
reads and Key Vault Secrets Officer for writes.

### Google Cloud Secret Manager

Each key is one secret in the configured project; every `Put` adds a version
and reads access `latest`. Versions are Secret Manager's own numeric IDs.
Secret IDs allow `[A-Za-z0-9_-]` and are case-sensitive, so only `/`, `.`
and `-` are escaped: `payments/prod/DB_URL` is stored as
`payments-1prod-1DB_URL`, with the canonical key in the `vaultlet-key`
annotation. Secrets that do not follow the encoding, have no versions, or
whose latest version is disabled or destroyed are ignored by `List` and
`Watch`.

`List` walks the whole project and needs one extra call per matching secret
to learn its current version, so a watch on a large project costs
`1 + N` requests per poll. `Delete` is permanent and removes every version.

Credentials come from Application Default Credentials unless
`credentials_file` names a service-account key. The identity needs
`roles/secretmanager.secretAccessor` plus `secretmanager.secrets.list` and
`secretmanager.versions.get` (Secret Manager Viewer) for reads, and
Secret Manager Admin for writes.

One server instance serves **one** backend. To serve several, either run one
instance per backend, or use the namespace-routing store (see Roadmap).

Write operations against a read-only backend return `ports.ErrReadOnly`, which
the gRPC layer maps to `FailedPrecondition`.

---

## Using it from CI

The job never holds a long-lived credential. It exchanges its OIDC token for a
short-lived vaultlet session.

```yaml
deploy:
  image: ghcr.io/ibiliaze/vaultlet-cli:1
  id_tokens:
    VAULTLET_JWT:
      aud: vaultlet
  script:
    - vaultlet login --oidc "$VAULTLET_JWT" --server vaultlet.internal:8443

    # Export into the shell
    - eval "$(vaultlet env payments/prod --format shell)"

    # Or render to a file
    - vaultlet get payments/prod/kubeconfig --out ./kubeconfig

    # Or wrap a command so values never touch disk or the log
    - vaultlet exec payments/prod -- ./deploy.sh
```

The only CI variables needed are the server address and CA certificate.

`vaultlet exec` masks fetched values in the child process's stdout. Nothing
prevents a script from printing a secret deliberately — masking is a guardrail,
not a control.

---

## Development

### Prerequisites

```
go 1.23+
buf            # proto linting and codegen
golangci-lint
```

### Common tasks

```bash
make generate     # buf generate → api/proto/gen
make lint         # golangci-lint, includes depguard boundary rules
make test         # unit tests, no network
make test-integration   # testcontainers; requires Docker
make build        # binaries into ./bin
make run          # server with examples/dev.yaml
```

### Testing strategy

- **`internal/domain`** — table tests, pure functions, no fakes needed.
- **`internal/app`** — in-memory fakes for every port. No network, no Docker,
  sub-millisecond. If a test here needs a real adapter, the layering is wrong.
- **`test/conformance`** — `RunSecretStoreTests(t, factory)` runs the same
  scenarios against every backend. A new adapter is "done" when it passes.
- **`internal/adapters/*`** — integration tests behind the `integration` build
  tag, using testcontainers or a recorded HTTP transport.

### Adding a backend

1. `internal/adapters/<name>/` with `store.go`, `config.go`, `mapper.go`.
2. Define `Config` **in the adapter package** and add a field for it to
   `config.Config`. The arrow points `config → adapter`, never back.
3. `var _ ports.SecretStore = (*Store)(nil)` for a compile-time check.
4. Add a case to `newStore` in `cmd/vaultlet/main.go`.
5. Wire it into `test/conformance` and make it pass.
6. Implement `Watch`. Without native notification, return
   `watch.Poll(ctx, ns, interval, s.List)` and enforce a poll-interval floor
   in `Config.Validate`, as the Bitwarden and Azure adapters do.

Map vendor errors to `ports.ErrNotFound` / `ErrReadOnly` / `ErrUnavailable` in
the adapter. Vendor error types must not escape the package.

### Conventions

- `main()` does nothing but call `run() error`, so deferred cleanup actually runs.
- Adapters return the port interface, not the concrete type, wherever the
  composition root consumes them.
- Optional capabilities (`Watcher`, `io.Closer`) are probed with type assertions
  rather than forced into the primary port.
- `domain.Secret.String()` redacts the value. Never log a raw value; never add a
  field to a struct that a logger might reflect over.

---

## Security notes

- Secret values are held as `[]byte`, copied defensively on construction and on
  read, and never placed in a `String()` or error message.
- Transport is TLS-only. mTLS for workloads, OIDC bearer for CI.
- Session tokens are short-lived (default 15 minutes) and bound to the principal
  that requested them.
- The audit sink records denials as well as successes — a burst of
  `PermissionDenied` for one principal is the signal worth alerting on.
- vaultlet inherits the blast radius of its backend credential. Scope the
  Bitwarden machine account or AWS role to exactly the projects it serves.

---

## Roadmap

**v0.1** — domain, app, file backend, gRPC server, CLI, conformance suite.

**v0.2** — Bitwarden adapter, polling watcher, OIDC auth for GitLab, policy engine.

**v0.3** — AWS adapter, audit to Postgres, OpenTelemetry traces and metrics,
Helm chart, goreleaser.

**Later**

- **Namespace routing** — mount different backends at different prefixes
  (`payments/**` → Bitwarden, `platform/**` → AWS). The router is itself a
  `ports.SecretStore`, so nothing in the core changes.
- **go-plugin backends** — run adapters out of process over gRPC, the way
  Terraform providers work. gRPC on both sides of the hexagon.
- **Read-only observability UI** — who accessed what, current subscribers, policy
  explorer. Not a secrets editor.

---

## Decisions

See `docs/adr/`:

- ADR-001 — Ports and adapters over a layered package structure
- ADR-002 — Opaque, unordered `Version`
- ADR-003 — Watch via optional interface plus polling fallback
- ADR-004 — Read-mostly: secrets are managed in the backend's own UI
- ADR-005 — Single backend per instance; routing deferred

---

## Licence

MIT. See [LICENSE](LICENSE).
