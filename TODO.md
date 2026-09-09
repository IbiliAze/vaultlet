# vaultlet — outstanding work

Baseline status as of 2026-09-01 (`89b0bdc`); §1.4 and related logging/test
notes updated 2026-09-05 against the working tree. `GetSecret`,
`ListSecrets` and `DeleteSecret` are implemented and verified end to end against
Bitwarden; `PutSecret` is implemented but untested against a write-enabled token.

Ordered roughly by impact. The suggested sequence is at the bottom.

---

## 1. Functional gaps

### 1.1 WatchSecrets is scaffolded, not working

- [ ] In progress. Status as of 2026-09-09 (`47f9671` plus an uncommitted
      poller draft in `bitwarden.go`). Every layer has a `Watch` signature
      and the tree builds, but no event has ever reached a client: the
      poller draft deadlocks before returning, and the gRPC handler still
      discards the channel. `go test ./...` fails to compile `internal/app`
      because the fake store's `Watch` has no body.

Purpose: a workload subscribes to a namespace once and is told when a secret
under it changes, instead of polling `List` or restarting on rotation. Events
carry metadata only; the client reads a rotated value with `GetSecret`, so
secret bytes stay on a path that is policy-checked and audited per read.

Design as built: `Watch` was added directly to `ports.SecretStore`
(`63940c7`), not as an optional `ports.Watcher` with a polling decorator as the
README describes. That means every backend must implement `Watch`, and a
polling loop written inside the Bitwarden adapter will have to be duplicated
or extracted when the AWS backend arrives. Either accept that and fix the
README's Watch section, or move the loop into `internal/adapters/driven/watch`
now while it is still empty. Decide before writing the loop.

Checklist:

- [x] **Domain.** `domain.SecretEvent` and the `Added` / `Updated` /
      `Deleted` / `InSync` constants exist (`e2b841d`, `1dd3f01`). The enum is
      named `domain.Type`, which reads poorly next to `domain.Key` and
      `domain.Secret`; `EventType` would be clearer. The field is embedded
      rather than named, which works but is unusual.
- [x] **Port.** `Watch(ctx, ns) (<-chan domain.SecretEvent, error)` is on
      `SecretStore`. The contract is not documented: snapshot then one
      `InSync` then live events, channel closed on cancellation or backend
      failure, no indefinite block on a slow consumer. Write it on the
      interface.
- [ ] **Fix the test fake.** `fakeStore.Watch` in `service_test.go:70` is a
      declaration without a body, so the app package does not compile under
      test. Return a closed channel or a small buffered one.
- [ ] **Polling loop.** A first draft is in the working tree
      (`bitwarden.go:274`). The map, ticker and version comparison are the
      right shape. What must change before it can run:
      - The initial snapshot sends on the unbuffered channel *before*
        `Watch` returns it, so the first `c <- ...` blocks forever and no
        caller ever gets the channel. Move the snapshot inside the
        goroutine; `Watch` should only create the channel, start the
        goroutine, and return.
      - The channel is never closed. `defer close(c)` at the top of the
        goroutine, so the handler's receive loop ends when `ctx` does.
      - Every send must `select` on `ctx.Done()` as well, otherwise a
        client that disconnects mid-send leaks the goroutine.
      - `ctx.Done()` as a bare statement does nothing; it returns a
        channel. Delete both occurrences.
      - `InSync` is emitted on every unchanged key on every tick. The proto
        allows exactly one, after the snapshot. Drop the `else` branch.
      - `Deleted` is never emitted. After walking the fresh list, any key
        still in the map but absent from the list is gone: emit `Deleted`
        with the stored meta and remove it from the map.
      - A failed poll returns from the goroutine, tearing the stream down
        on a transient error. Log it and wait for the next tick instead.
      - `time.NewTicker` panics on a non-positive interval; the config
        floor below is what protects it.
      - Style: `switch exists { case false: ... case true: ... }` is an
        `if`/`else`; `mMap[existingMeta.Key.String()]` is the same key as
        `meta.Key.String()`.
- [x] **Poll interval.** `Config.Validate` requires `poll_interval`
      (`1dd3f01`) and the draft threads it into `Store.pollingInterval`.
      Still needs a floor (1s or so) so a typo cannot hammer the backend or
      panic the ticker.
- [ ] **App layer.** `Service.Watch` exists but has three problems. It gates
      on `canList`, so a principal with `watch` but not `list` is denied and
      vice versa; add a `canWatch` or generalise `canList` over an action.
      When the store returns an error it audits `error` and then returns
      `c, nil`, handing the caller a nil channel with no error. And events
      are not filtered: a subscriber to an ancestor namespace receives every
      key beneath it, where `List` filters each result by policy. Wrap the
      store's channel and drop events the principal may not see.
- [ ] **gRPC handler.** `WatchSecrets` in `handlers.go:149` uses
      `context.Background()` instead of `server.Context()`, so the principal
      set by `streamAuth` is lost and every call is denied; it also ignores
      client cancellation. The raw `ErrPermissionDenied` is returned without
      mapping to `PERMISSION_DENIED`, and the channel is discarded without a
      receive loop. Needs: stream context, error mapping as in
      `ListSecrets`, a `for ev := range c` loop translating to
      `vaultletv1.SecretEvent` and calling `Send`, and `nil` on cancellation.
- [ ] **Tests.** Store loop against a fake `List`: snapshot then `InSync`,
      each diff case, cancellation closes the channel, failed poll does not.
      Service: denied subscribe never reaches the store, ancestor filtering,
      one audit record. Handler: event mapping, `PERMISSION_DENIED`,
      cancellation returns `nil`.
- [ ] **Verify live** against Bitwarden: subscribe, edit a secret in the
      Bitwarden UI, confirm `UPDATED` arrives within one poll interval, and
      `vaultlet get` returns the new value.
- [ ] **Docs.** Reconcile the README's Watch section with whichever design
      is kept, and drop the §1.4 note that watch policy/audit belongs here.

Note that `versionAt` derives the version from `RevisionDate`, so an UPDATED
event is detectable as a version change on an unchanged key.

### 1.2 Compare-and-swap

- [x] `DeleteSecret` now rejects `expected_version` with `Unimplemented`,
      matching `PutSecret` (`ad85107`). The two RPCs are consistent and no
      longer mislead callers.
- [ ] Real compare-and-swap is still unimplemented.

Real CAS needs an `expectedVersion` parameter on `SecretStore.Put` and
`.Delete`, plus `ports.ErrVersionMismatch` mapped to `ABORTED`. Bitwarden has no
native CAS, so it would be a read-compare-write with a race window — which is
worth saying out loud in the adapter rather than pretending otherwise. Until
then `--expected-version` on the CLI is a flag that can only ever fail; consider
hiding it.

### 1.3 No TLS on the server

- [x] Done (`89b0bdc`). `config.TLSConfig` (`tls.cert_file` / `tls.key_file`
      in `vaultlet.yaml`) feeds `grpcserver.New(store, cfg.TLS)`, which builds
      the server with `grpc.Creds(...)` via `credentials.NewServerTLSFromFile`.
      TLS is mandatory — there is no plaintext mode — and `Validate()` rejects
      missing cert/key paths with clear messages before startup.
- [x] Verified live: booted with the self-signed dev cert in `cert/`
      (gitignored), `openssl s_client -CAfile cert/cert.pem` handshakes
      TLSv1.3 with verify code 0, and SIGTERM still drains cleanly through
      the new code path.

- [x] The TLS 1.3 floor nit is resolved (uncommitted): `New` now uses
      `tls.LoadX509KeyPair` + `credentials.NewTLS(&tls.Config{MinVersion:
      tls.VersionTLS13})`, matching the client's pin. Verified live: openssl
      handshakes at 1.3 with verify code 0, and a forced `-tls1_2` client is
      rejected with a protocol-version alert. The explicit `tls.Config` is
      also where `ClientCAs`/`ClientAuth` would go if mTLS is ever wanted.

Nothing remains; §1.3 is complete.

### 1.4 Authentication, authorization and audit

- [x] Authentication implemented. The CLI sends `--token` /
      `$VAULTLET_TOKEN` — base64("user:password") — as `authorization: Basic`
      per-RPC credentials (`tokenCreds` refuses plaintext transport). The
      server verifies it in unary + stream interceptors (`grpcserver/auth.go`)
      against bcrypt hashes in `auth.users`, answering every failure mode with
      the same `UNAUTHENTICATED "invalid credentials"` (unknown users burn a
      dummy bcrypt compare so timing matches). The principal lands in the
      context via `app.WithPrincipal`. Verified live: no token, wrong
      password, and malformed token all rejected; valid token lists secrets.
- [x] Authorization implemented. Startup compiles per-user `allow` rules
      (namespace + actions) into an `app.Policy` and passes an `app.Service`
      wrapper to gRPC. Checks deny by default using `Namespace.Contains`;
      all four handlers map `app.ErrPermissionDenied` to `PERMISSION_DENIED`.
- [x] List filtering implemented. `canList` permits requests overlapping a
      namespace the principal may list, including ancestor and empty-namespace
      requests. Each result must be within both the requested namespace and
      a rule granting `list`. Requests with no permitted overlap skip the
      backend and return permission denied.
- [x] Application audit implemented. Get, Put, List and Delete emit one record
      per normal return path with principal, action, key (namespace for List),
      decision and outcome. Records contain no values, credentials or raw
      backend errors. The default server logger writes JSON to stderr.
- [x] RPC logging implemented in unary and stream interceptors, registered
      before authentication so rejected credentials are logged too. Records
      include method, duration in milliseconds and returned gRPC status;
      streaming duration covers the handler's lifetime. This absorbs §2.5.
- [ ] Behavioral verification remains: allowed and denied operations, denied
      calls skipping the backend, List filtering for ancestor/empty namespaces
      and segment boundaries, backend failures, one audit record per service
      call, and RPC completion logging for success/authentication/policy errors.

Implementation is complete for the current Get/Put/List/Delete surface.
`go test ./...` passes, but there are no tests yet; this confirms compilation,
not runtime authorization or audit behavior. Authentication's earlier live
verification is recorded above. Watch policy/audit belongs with §1.1 when that
RPC is implemented.

### 1.5 Read-only backends (`ports.ErrReadOnly`)

- [x] Done (`02eac5a`). `ports.ErrReadOnly` is declared alongside `ErrNotFound`
      and wrapped by the adapter as `fmt.Errorf("bitwarden: %w", ...)`, so
      `errors.Is` works across the port boundary.
- [x] `bitwarden.Config.AllowWrites` (`allow_writes` in `vaultlet.yaml`) gates
      both writes: `Put` and `Delete` return `ErrReadOnly`, `Get` and `List`
      are unaffected.
- [x] `PutSecret` and `DeleteSecret` map it to `FAILED_PRECONDITION` with a
      fixed "backend is read-only" message, ahead of the `ErrNotFound` and
      `ErrEmptyValue` branches so it cannot be shadowed. The backend name is not
      leaked to clients, per the proto's design note.

Open question, not a defect: `vaultlet.yaml` ships `allow_writes: true`, so the
zero value is permissive. Deny-by-default would fail safe for a service the
proto describes as "read-mostly". Worth deciding deliberately.

---

## 2. Bugs

### 2.1 `make build` does not stamp the version

- [x] Fixed. `CLI_PKG` now points at `internal/adapters/driving/cli`
      (`3f73bf3`); `make build && ./bin/vaultlet-cli version` reports
      `vaultlet 6b8fd65 (commit 6b8fd65, built 2026-08-31T19:03:52Z)`.
      The `root.go` doc comment was corrected too.
- [x] The last stale path in `cmd/vaultlet-cli/main.go:3` was corrected
      (`49c8a54`). No `internal/adapters/cli` references remain.

### 2.2 `config.Load` discards both load errors

- [x] Fixed (`6b8fd65`). Both `k.Load` calls are now checked, with
      `errors.Is(err, fs.ErrNotExist)` tolerating a missing `vaultlet.yaml` or
      `.env`, and the env-provider error propagated.
- [x] `Config.Validate()` was added and is called from `cmd/vaultlet/main.go`
      before the backend is opened. It covers `Backend` and `Listen`.

### 2.3 The server cannot shut down cleanly

- [x] `server.go` moved off `log` onto `slog`.
- [x] Graceful shutdown implemented (`d096586`). `run()` builds a
      signal-aware context via `signal.NotifyContext` (SIGINT/SIGTERM);
      `Listen` runs `Serve` in a goroutine and selects on `ctx.Done()`, then
      drains via `GracefulStop` bounded by a 10s `shutdownTimeout` with a
      forced `Stop()` fallback.
- [x] The nil-listener regression is fixed in the same change: `Listen`
      returns an `error` for both `net.Listen` and `Serve` failures, and
      `run()` propagates it.
- [x] Bonus fix found along the way: the `store.(interface{ Close() error })`
      assertion in `main.go` never matched the Bitwarden store's `Close()`
      (no error return), so the FFI handle leaked on every exit. Now asserts
      `interface{ Close() }`.

### 2.4 `domain.Namespace.Matches` is an unfinished stub

- [x] Resolved (`6b8fd65`) by dropping the dangling comment. `key.go` now ends
      cleanly at `Contains`. Glob matching remains unimplemented, which is fine
      — nothing depends on it.

### 2.5 Per-RPC invocation logging

- [x] The copy-paste slip introduced in `e5d8406` is fixed (`49c8a54`): each
      handler now names its own RPC rather than all four claiming `GetSecret`.
- [x] Unary and stream logging interceptors now use `slog.InfoContext` to
      record method, duration and returned status, including authentication
      failures. The four bare "invoked" lines are removed; handler error logs
      remain. Key/namespace and principal details live in the application
      audit records described in §1.4.

Implementation complete; behavioral verification is tracked in §1.4.

---

## 3. Missing scaffolding

### 3.1 No tests

- [ ] Not started. Still no `_test.go` anywhere in the repo, though `make test`
      exists.

- `domain`: `ParseKey`, `ParseNamespace`, `Namespace.Contains` are pure
  functions against a documented grammar. Cheapest, highest-value tests here.
- `app`: policy enforcement, filtered listings and audit records, including
  denied calls never reaching the backend (see §1.4).
- `grpcserver`: the handlers are testable against a fake `ports.SecretStore` —
  particularly the error mapping (`ErrNotFound` → `NOT_FOUND`, `ErrEmptyValue` →
  `INVALID_ARGUMENT`, empty namespace → list everything, non-empty page token →
  rejected, `expected_version` → `UNIMPLEMENTED` on both put and delete).
  Also cover `ErrPermissionDenied` → `PERMISSION_DENIED` and interceptor
  completion records for successful calls and authentication/policy failures.
- `cli`: `NewRootCmd` returns a `*cobra.Command` specifically so "tests can
  execute commands with their own args and output buffers" — a seam nothing
  currently uses.

### 3.2 Pagination is server-side unimplemented

- [ ] Not started.

`ListSecrets` ignores `page_size` and always returns one page. This is legal per
the proto ("server may return fewer than requested") and the CLI already loops
on `next_page_token`, so it can wait — but it will matter on a large org.

### 3.3 Second backend

- [ ] Not started.

`internal/adapters/driven/aws/` is an empty directory. A second backend is the
whole point of the ports design and the best proof the abstraction holds.

---

## 4. Smaller items

- [ ] `list.go` uses `cobra.ExactArgs(1)`, so the CLI cannot reach the
      empty-namespace "list everything" the server now supports.
      `cobra.MaximumNArgs(1)` opens it up.
- [ ] `resolveID` lists the entire organization on every Get, Put and Delete.
      The comment acknowledges the cost; it will bite once the vault is
      non-trivial. A short-lived name→UUID cache is the obvious mitigation.
- [ ] A permissions gap and a genuinely absent secret are indistinguishable to
      the caller — both surface as `NOT_FOUND`. An org listing that returns zero
      rows overall is far more likely to be a misconfigured machine account than
      an empty vault, and is worth logging as such in `resolveID`. (Confirmed in
      practice: a machine account with no project access reads as an empty org.)
- [x] `ListSecretsResponse{..., NextPageToken: ""}` — the explicit zero value
      was dropped (`49c8a54`).
- [x] Stray blank lines before a closing brace in the read-only guards
      (`handlers.go` `DeleteSecret`, `bitwarden.go` `Delete`) — removed
      (uncommitted). All three sites are now clean.

---

## Suggested order

1. Domain, app and handler/interceptor tests, including the authorization and
   audit verification in §1.4.
2. `WatchSecrets`, including the port change and the Bitwarden polling loop.
