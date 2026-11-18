# DEP #981: independent standalone refresh grants

## Summary

A client can opt into multiple independent refresh grants per user and connector
with `refreshTokenLimit`. Each successful login issues a separate grant with its
own rotating secret. User identity and ID-token subject are unchanged. The
proposal addresses [dexidp/dex#981](https://github.com/dexidp/dex/issues/981).

This implementation is based on **v2.46.1** in a personal fork. It also backports
upstream fixes #4991, #5129, #5082, #5067 and #5133 for rotation deadlocks,
concurrent revocation, credential logging and rollback after storage failures.

## Motivation

A kubeconfig distributor such as loginapp should be able to issue a different
configuration for each device without invalidating earlier configurations for
the same user and OAuth client. Currently the offline-session index retains only
one refresh grant per client; another login replaces it.

Each device must obtain its **own new configuration through a login/code
exchange**. Copying the same kubeconfig to multiple devices still copies a single
rotating secret and still causes conflicts. There is no device fingerprinting,
no change to `sub`, and no Google connector or loginapp code change required.
Multiple exchanges from the same browser also produce independent grants.

## Proposal

### Client policy

| `refreshTokenLimit` | New login requesting a refresh token |
| --- | --- |
| omitted or `0` | Existing behavior: replace the legacy grant for this client |
| positive `N` | Issue an independent grant if fewer than `N` grants exist; otherwise reject |

The quota is scoped to `(user ID, connector ID, client ID)`. A legacy grant counts
against a newly enabled limit. `1` deliberately differs from `0`: a second login
is rejected instead of replacing the existing grant. Decreasing the limit never
evicts a grant; new issuance waits until the count falls below the new limit.
Expired and revoked grants release capacity. Requests without `offline_access`
are unaffected.

At capacity the token endpoint returns HTTP 400, OAuth `invalid_grant`, and an
`error_description` explaining that an existing grant must be revoked. No access,
ID, or refresh token is returned. Authorization codes remain single use: after a
failed exchange, start another authorization. Device-flow callbacks record a
terminal quota error so the polling device receives the same error rather than
polling indefinitely.

This first version supports **standalone** refresh tokens. Configuration and API
validation reject a positive limit combined with `refreshTokenLifetime: session`.
Auth Sessions need not be enabled. If sessions are enabled, the originating `sid`
is retained, but ordinary browser logout does not end standalone grants.
Existing administrative session termination remains broader and can revoke them.

Expiration and rotation continue to use the global `expiry.refreshTokens`
policy. There is no per-client TTL, LRU eviction, or change to reuse intervals.
Revoking a refresh grant does not invalidate already issued ID-token JWTs. Their
expiration remains relevant to Kubernetes access.

### Configuration example

For a static client, update Dex configuration (the gRPC client CRUD API cannot
change static clients):

```yaml
staticClients:
- id: loginapp
  name: Kubernetes login
  secretEnv: LOGINAPP_CLIENT_SECRET
  redirectURIs:
  - https://login.example.com/callback
  refreshTokenLifetime: standalone
  refreshTokenLimit: 50

expiry:
  refreshTokens:
    absoluteLifetime: 2160h
    validIfNotUsedFor: 720h
    reuseInterval: 3s
```

The TTLs and quota above are examples, not new defaults. Choose them for the
operator's access and revocation policy. The limit counts grants, not physical
devices; repeatedly downloading a new configuration consumes more slots.

For a dynamic client, use the generated Go API client over the existing protected
gRPC connection:

```go
_, err := client.UpdateClient(ctx, &api.UpdateClientReq{
    Id: "loginapp", RefreshTokenLimit: proto.Uint32(50),
})
```

`Client` and `ClientInfo` expose the limit. `UpdateClientReq.refresh_token_limit`
has explicit presence: omission (including requests from older clients) preserves
the current value; an explicit `0` disables new independent issuance.

### Listing and revocation

`user_id` is the opaque Dex ID-token `sub`, not a Google email address. Listing is
scoped to that user's connector and uses the offline-session indexes, never a
scan of the global refresh-token table.

```go
listed, err := client.ListRefresh(ctx, &api.ListRefreshReq{UserId: subject})
// Choose a listed grant by its client_id and id.
revoked, err := client.RevokeRefreshToken(ctx, &api.RevokeRefreshTokenReq{
    UserId: subject, ClientId: "loginapp", RefreshTokenId: grantID,
})
// Existing RPC now revokes all of this user's grants for that client.
all, err := client.RevokeRefresh(ctx, &api.RevokeRefreshReq{
    UserId: subject, ClientId: "loginapp",
})
```

The single-grant RPC verifies the user/connector/client index membership. An
unknown ID or ownership mismatch returns `not_found` without touching another
grant. It is a separate RPC so an older server returns `Unimplemented`; an older
server cannot silently ignore a new selector and revoke every grant instead.
`ListRefresh` includes indexed grant metadata, including any expired grant awaiting
cleanup; it does not expose bearer secrets. The API remains administrative, with
the same transport/access controls as the existing revocation RPC.

### Storage and concurrency

The existing `OfflineSessions.Refresh` map stays keyed by client ID. The new
`RefreshTokens` map is keyed by grant ID. Lookups, rotation and revocation use
shared helpers across both indexes. Disabling the limit resumes replacement in
the legacy map while independent grants remain usable until expiry or revocation.

Registration checks the quota and adds a reference in one atomic offline-session
update. Concurrent first logins create an empty session with create-if-absent and
then retry the update. Memory copies index maps on reads and updates. Kubernetes
uses resource-version CAS, etcd retries CAS, and SQL/ent use serializable
transactions with bounded, jittered retries for known conflicts. No updater calls
storage or an upstream connector from inside a transaction.

Issuance first stores a `pending` row, then registers it, then activates it. Empty
state means active, including pre-upgrade rows. Neither pending nor revoked rows
are accepted. Refresh and introspection also require exact index membership, so
an orphan row is not a usable credential. Failed registration/activation rolls
back its reference and row; failed deletion is recoverable. An interrupted
pending issuance has a five-minute lease and can then be collected. A process
resuming after collection cannot activate a deleted/tombstoned row.

Expiration is checked on the canonical row in an atomic updater before marking
it `revoked`, removing its reference, and deleting it. The potentially stale
`LastUsed` in the index is never sufficient to expire a token. Rotation cannot
revive a tombstoned row. A paged background sweep (100 rows per page) cleans up
expired, abandoned and orphan rows; admission checks only the user's indexed
grants. SQL/ent use ordered key pagination, etcd uses a bounded key range, and
Kubernetes follows continuation tokens without reusing a resource version.
Orphan references to already missing rows are repaired on the next admission.

SQL migrations append `client.refresh_token_limit` (default 0), nullable
`offline_session.refresh_tokens`, and `refresh_token.state` (default empty).
Ent schemas and generated bindings, Kubernetes JSON and etcd JSON carry the same
fields. Existing IDs, secrets and references are not rewritten.

### Rollout, compatibility and rollback

1. Back up storage. Upgrade **every replica** with all limits still zero.
2. Verify startup, migration and existing-client refresh on the new binary.
3. Enable a positive limit on selected standalone clients.
4. Issue a fresh configuration separately for each device. Retire copied configs.

Running an old binary while independent grants are enabled is unsupported: it
cannot preserve the new index or apply its revocation semantics. A rollback before
activation is compatible with the additive schema. After activation, first stop
new independent issuance (set limits to zero), then revoke or let all independent
grants expire, allow cleanup to finish, and only then downgrade. Setting the limit
to zero alone does not invalidate or migrate existing grants. SQL columns should
be left in place when rolling back; restore from a backup if schema restoration
is required.

The SQL migration list in this fork has an extra numbered migration after
v2.46.1. A later upstream release can assign that number to an unrelated change.
**Do not switch this database directly to a later upstream binary.** Reconcile
migration histories and explicitly test that upgrade, or migrate into a clean
upstream database after draining/revoking grants. Preserve backups throughout.
This PR does not deploy the fork or change a cluster's configuration.

### Risks and mitigations

- A larger quota permits more simultaneous credentials. It is opt-in, finite,
  uses the existing TTL policy, and provides both targeted and broad revocation.
- Storage writes span more than one record. Pending/revoked states, mandatory
  membership checks, compensation and conditional collection fail closed after
  partial writes. During storage outages issuance can fail or temporarily reserve
  quota until cleanup succeeds.
- Upstream connector credentials remain shared at the user/connector level as in
  v2.46.1. This proposal does not provide a new serialization protocol for an IdP
  that rotates its own refresh token on every use. Google-specific live OAuth
  testing still requires a real configured Google client and user consent.
- Index size grows with the configured quota. There is no automatic eviction;
  operators should keep limits bounded and monitor storage and issuance errors.

### Alternatives

Separate OAuth client IDs per device distort application registration and
administration. Changing the user ID per login changes `sub` and breaks identity
and RBAC. Disabling rotation or extending its reuse interval does not create
independent revocation/expiry domains. Auth Sessions manage browser SSO and
session-bound lifetime; they do not distinguish multiple standalone grants.

## Validation

The regression suite covers independent rotations, unchanged subjects, quota
rejection without partial credentials, same-browser origin, first-login races
across store instances, lowered/disabled limits, expiry and stale-index cleanup,
interrupted issuance/restart, failed deletion and orphan rejection, API ownership
and optional-field compatibility, and standalone grants surviving browser logout.
HTTP tests exercise authorization code, password and device flows with a
reproducible mock connector. Storage conformance covers round trips, paging while
deleting, transaction rollback and concurrent admission; the migration test
loads the pre-change SQL schema and credentials before upgrading.

Run `make testall`, `make lint`, `make verify` and `make build` with Go 1.27.
Configure the repository's `DEX_*` integration-test environment variables for
PostgreSQL, MySQL 5.7/8.0 (SQL and ent), etcd and an isolated Kubernetes cluster.
These checks do not establish successful login against a live Google tenant.

## Future improvements

A device/grant management UI, labels and last-seen metadata; a separately designed
session-bound mode; per-client lifetime policies; and upstream-provider refresh
coordination are outside this PR.
