# Independent refresh grants on Dex v2.42.0

Set `refreshTokenLimit` on the **static OAuth client that requests `offline_access`**.
For example, on the existing `kubernetes` client used by Loginapp:

```yaml
staticClients:
- id: kubernetes
  name: Kubernetes login
  secretEnv: KUBERNETES_CLIENT_SECRET
  redirectURIs:
  - https://login.example.com/callback
  refreshTokenLimit: 5
```

Sign in and download a new kubeconfig separately for each device. Each issuance
has its own Dex refresh token and rotation history. Copies of a single kubeconfig
still share that credential. The ID-token subject and the connector stay the same.

An omitted or zero limit keeps legacy issuance. A positive limit caps grants per
user, connector, and client, including an existing legacy grant. A new offline
login at capacity fails without evicting an active grant. Requests without
`offline_access` are unaffected. Reducing the limit preserves existing grants,
and setting it to zero resumes legacy issuance while retaining independent grants.

Existing `expiry.refreshTokens` settings apply to all the grants. When an offline
login is admitted, Dex checks each indexed row's current expiry, retires expired
secrets, and then releases their slots. A device-flow grant stays pending until
the device polls its completed response. If the response is never delivered, the
pending slot is released on the next offline login after the device code expires.
Set a refresh-token lifetime to reclaim slots even when a device is lost after
receiving its token. Google continues to use the existing upstream credential
handling; only Dex grants rotate independently.

On the administrative gRPC API, `ListRefresh` lists grants for an ID-token `sub`.
`RevokeRefreshToken` takes that subject, the client ID, and the grant ID from
`ListRefresh`. `RevokeRefresh` revokes all grants for the specified client and
subject. Cached ID tokens remain usable until their own expiry.

The grants are stored in the existing offline-session index. No schema migration
is required. Refresh and introspection require the exact reference. Revocation
deletes the token row before removing its reference. A deletion failure is
reported, and the operation can be retried. Deploy the new binary to every Dex
replica before setting a positive limit. Before downgrading, disable independent
issuance and revoke all independent grants while running the new binary. An old
replica cannot preserve their index entries. An interrupted issuance or failed
cleanup can leave unreferenced rows in storage. They cannot refresh on this
binary or take up quota, but a pre-upgrade binary may report them active through
introspection. Check and remove such rows before downgrading. If the connection
drops after registration, the grant may count until expiry or explicit revocation
even if the caller missed the response.
