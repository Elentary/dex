package tokens

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
)

// RefreshStore creates, rotates, and revokes refresh tokens, keeping the
// offline-session references in sync. It is the single owner of refresh-token
// persistence.
type RefreshStore struct {
	storage  storage.Storage
	now      func() time.Time
	logger   *slog.Logger
	strategy *RefreshStrategy
}

// NewRefreshStore returns a store backed by the given storage.
func NewRefreshStore(storage storage.Storage, now func() time.Time, logger *slog.Logger, policy ...*RefreshStrategy) *RefreshStore {
	strategy := NewRefreshStrategy(true, 0, 0, 0, now)
	if len(policy) > 0 && policy[0] != nil {
		strategy = policy[0]
	}
	return &RefreshStore{storage: storage, now: now, logger: logger, strategy: strategy}
}

// ErrRefreshTokenLimit means an independent grant would exceed the client's quota.
var ErrRefreshTokenLimit = errors.New("refresh token limit reached; revoke an existing grant before signing in again")

// Create registers a new grant atomically with its quota check, then activates
// it. Failed writes are compensated; unfinished rows remain unusable.
func (rt *RefreshStore) Create(ctx context.Context, auth Authorization) (string, error) {
	if err := auth.Client.ValidateRefreshTokenPolicy(); err != nil {
		return "", err
	}
	if auth.Client.RefreshTokenLimit > 0 {
		if err := rt.prune(ctx, auth.Claims.UserID, auth.ConnectorID, auth.Client.ID); err != nil {
			return "", err
		}
	}
	now := rt.now()
	refresh := storage.RefreshToken{
		ID: storage.NewID(), Token: storage.NewID(), State: storage.RefreshTokenPending,
		ClientID: auth.Client.ID, ConnectorID: auth.ConnectorID, Scopes: auth.Scopes,
		Claims: auth.Claims, Nonce: auth.Nonce, ConnectorData: auth.ConnectorData,
		CreatedAt: now, LastUsed: now,
	}
	raw, err := internal.Marshal(&internal.RefreshToken{RefreshId: refresh.ID, Token: refresh.Token})
	if err != nil {
		return "", err
	}
	if err := rt.storage.CreateRefresh(ctx, refresh); err != nil {
		return "", fmt.Errorf("create refresh token: %w", err)
	}
	ref := &storage.RefreshTokenRef{ID: refresh.ID, ClientID: refresh.ClientID, CreatedAt: now, LastUsed: now, SessionID: auth.SessionID}
	var replaced *storage.RefreshTokenRef
	// The callback can run again after a CAS/serialization conflict. All reads,
	// quota decisions and reference mutations belong to this one transaction.
	register := func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
		replaced = nil
		if auth.Client.RefreshTokenLimit > 0 {
			var count uint64
			for _, r := range old.RefreshTokenRefs() {
				if r.ClientID == ref.ClientID {
					count++
				}
			}
			if count >= uint64(auth.Client.RefreshTokenLimit) {
				return old, ErrRefreshTokenLimit
			}
			if old.RefreshTokens == nil {
				old.RefreshTokens = make(map[string]*storage.RefreshTokenRef)
			}
			old.RefreshTokens[ref.ID] = ref
		} else {
			if old.Refresh == nil {
				old.Refresh = make(map[string]*storage.RefreshTokenRef)
			}
			replaced = old.Refresh[ref.ClientID]
			old.Refresh[ref.ClientID] = ref
		}
		if len(auth.ConnectorData) > 0 {
			old.ConnectorData = auth.ConnectorData
		}
		return old, nil
	}
	// A concurrent first login may create the offline session after our failed
	// update. Retry its atomic update instead of failing or overwriting it.
	err = rt.storage.UpdateOfflineSessions(ctx, auth.Claims.UserID, auth.ConnectorID, register)
	if errors.Is(err, storage.ErrNotFound) {
		err = rt.storage.CreateOfflineSessions(ctx, storage.OfflineSessions{UserID: auth.Claims.UserID, ConnID: auth.ConnectorID, Refresh: map[string]*storage.RefreshTokenRef{}})
		if err == nil || errors.Is(err, storage.ErrAlreadyExists) {
			err = rt.storage.UpdateOfflineSessions(ctx, auth.Claims.UserID, auth.ConnectorID, register)
		}
	}
	if err == nil {
		// GC may have abandoned a slow/crashed issuance. Only a still-pending row
		// can become usable; a tombstoned/deleted row must never be resurrected.
		err = rt.storage.UpdateRefreshToken(ctx, refresh.ID, func(old storage.RefreshToken) (storage.RefreshToken, error) {
			if old.State != storage.RefreshTokenPending {
				return old, ErrRefreshTokenInvalid
			}
			old.State = ""
			if auth.Client.RefreshTokenLimit > 0 {
				old.State = storage.RefreshTokenActive
			}
			return old, nil
		})
	}
	if err != nil {
		rt.rollbackCreate(ctx, refresh, replaced)
		return "", fmt.Errorf("register refresh token: %w", err)
	}
	if replaced != nil {
		if err := rt.storage.DeleteRefresh(ctx, replaced.ID); err != nil && !errors.Is(err, storage.ErrNotFound) {
			// Membership already changed atomically: the old row is unusable and
			// the paged sweep can finish deleting it after a storage failure.
			rt.logger.ErrorContext(ctx, "delete replaced refresh token", "err", err)
		}
	}
	return raw, nil
}

func (rt *RefreshStore) rollbackCreate(ctx context.Context, refresh storage.RefreshToken, replaced *storage.RefreshTokenRef) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	err := rt.storage.UpdateOfflineSessions(ctx, refresh.Claims.UserID, refresh.ConnectorID, func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
		if old.RefreshTokenRef(refresh.ClientID, refresh.ID) != nil {
			old.DeleteRefreshTokenRef(refresh.ClientID, refresh.ID)
			if replaced != nil {
				old.Refresh[refresh.ClientID] = replaced
			}
		}
		return old, nil
	})
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		rt.logger.ErrorContext(ctx, "undo refresh registration", "err", err)
	}
	if err := rt.storage.DeleteRefresh(ctx, refresh.ID); err != nil && !errors.Is(err, storage.ErrNotFound) {
		rt.logger.ErrorContext(ctx, "delete failed refresh issuance", "err", err)
	}
}

// IdentityFromClaims projects stored claims into a connector identity. The
// refresh flow intentionally leaves UserID untouched by later updates.
func IdentityFromClaims(claims storage.Claims) connector.Identity {
	return connector.Identity{
		UserID:            claims.UserID,
		Username:          claims.Username,
		PreferredUsername: claims.PreferredUsername,
		Email:             claims.Email,
		EmailVerified:     claims.EmailVerified,
		Groups:            claims.Groups,
	}
}

// ClaimsFromIdentity maps a freshly authenticated connector identity to ID token
// claims. It is the inverse of IdentityFromClaims and the single place grants
// turn an identity into claims.
func ClaimsFromIdentity(identity connector.Identity) storage.Claims {
	return storage.Claims{
		UserID:            identity.UserID,
		Username:          identity.Username,
		PreferredUsername: identity.PreferredUsername,
		Email:             identity.Email,
		EmailVerified:     identity.EmailVerified,
		Groups:            identity.Groups,
	}
}

// Rotate advances the stored refresh token according to the rotation strategy and
// syncs the offline session. It returns the marshaled token to hand back to the
// client and the identity its claims were refreshed to.
//
// Rotation runs as two storage transactions around the identity resolution: the
// claim reuses the token or rotates it, the finalize writes the refreshed claims.
// The updaters never read storage, so backends that serialize on one connection
// or lock (SQLite, memory) cannot deadlock. A concurrent refresh that lands
// between the two reuses the new token. A failed resolve, finalize or offline
// session update undoes the claim.
func (rt *RefreshStore) Rotate(ctx context.Context, storageToken *storage.RefreshToken, requestToken *internal.RefreshToken, strategy *RefreshStrategy, freshIdentity func(context.Context) (connector.Identity, error)) (string, connector.Identity, error) {
	newToken := &internal.RefreshToken{
		Token:     requestToken.Token,
		RefreshId: requestToken.RefreshId,
	}

	ident := IdentityFromClaims(storageToken.Claims)
	lastUsed := rt.now()
	mint := false
	var claimedFrom time.Time
	var prevObsolete string

	// Claim: decide reuse or rotation from the live row.
	claim := func(old storage.RefreshToken) (storage.RefreshToken, error) {
		// Reset per execution: a backend that retries the updater (kubernetes,
		// on conflict) must not carry a stale decision from an earlier run.
		mint = false
		if !old.IsActive() || strategy.CompletelyExpired(old.CreatedAt) || strategy.ExpiredBecauseUnused(old.LastUsed) {
			return old, ErrRefreshTokenInvalid
		}

		rotationEnabled := strategy.RotationEnabled()
		reusingAllowed := strategy.AllowedToReuse(old.LastUsed)

		switch {
		case !rotationEnabled && reusingAllowed:
			// Rotation disabled and the token was used recently: nothing to advance.
			old.ConnectorData = nil
			return old, nil

		case rotationEnabled && reusingAllowed:
			if old.Token != requestToken.Token && old.ObsoleteToken != requestToken.Token {
				return old, errors.New("refresh token claimed twice")
			}

			// Return the previously generated token for requests carrying an obsolete one.
			if old.ObsoleteToken == requestToken.Token {
				newToken.Token = old.Token
			}

			// Do not advance last-used while the token may still be reused.
			lastUsed = old.LastUsed
			old.ConnectorData = nil
			return old, nil

		case rotationEnabled && !reusingAllowed:
			if old.Token != requestToken.Token {
				return old, errors.New("refresh token claimed twice")
			}
		}

		// Rotate the token here, not in the finalize, so a concurrent refresh
		// reuses the new token instead of resolving the connector again.
		claimedFrom = old.LastUsed
		prevObsolete = old.ObsoleteToken
		old.LastUsed = lastUsed
		if strategy.RotationEnabled() {
			old.ObsoleteToken = old.Token
			newToken.Token = storage.NewID()
			old.Token = newToken.Token
		}
		old.ConnectorData = nil
		mint = true
		return old, nil
	}

	if err := rt.storage.UpdateRefreshToken(ctx, storageToken.ID, claim); err != nil {
		rt.logger.ErrorContext(ctx, "failed to claim refresh token rotation", "err", err)
		return "", ident, err
	}

	if mint {
		// Resolve the identity outside any transaction: the connector may read
		// storage (the password DB does) or contact an upstream provider.
		var idErr error
		ident, idErr = freshIdentity(ctx)
		if idErr != nil {
			rt.undoClaim(ctx, storageToken.ID, strategy.RotationEnabled(), newToken.Token, prevObsolete, lastUsed, claimedFrom)
			return "", ident, idErr
		}

		// Finalize: write the refreshed claims.
		finalize := func(old storage.RefreshToken) (storage.RefreshToken, error) {
			if !old.IsActive() || old.Token != newToken.Token {
				return old, errors.New("refresh token claimed twice")
			}

			// Refresh the stored claims. UserID intentionally left untouched.
			old.Claims.Username = ident.Username
			old.Claims.PreferredUsername = ident.PreferredUsername
			old.Claims.Email = ident.Email
			old.Claims.EmailVerified = ident.EmailVerified
			old.Claims.Groups = ident.Groups

			old.ConnectorData = nil
			return old, nil
		}

		if err := rt.storage.UpdateRefreshToken(ctx, storageToken.ID, finalize); err != nil {
			rt.logger.ErrorContext(ctx, "failed to finalize refresh token rotation", "err", err)
			rt.undoClaim(ctx, storageToken.ID, strategy.RotationEnabled(), newToken.Token, prevObsolete, lastUsed, claimedFrom)
			return "", ident, err
		}
	}

	if err := rt.updateOfflineSession(ctx, storageToken, ident, lastUsed); err != nil {
		if mint {
			rt.undoClaim(ctx, storageToken.ID, strategy.RotationEnabled(), newToken.Token, prevObsolete, lastUsed, claimedFrom)
		}
		return "", ident, err
	}

	rawToken, err := internal.Marshal(newToken)
	if err != nil {
		return "", ident, fmt.Errorf("marshal refresh token: %w", err)
	}

	return rawToken, ident, nil
}

// undoClaim rolls a claim back after a failed resolution, finalize or offline
// session update. The guard applies only to a row still showing our own claim;
// an undo that itself fails is logged and otherwise ignored.
func (rt *RefreshStore) undoClaim(ctx context.Context, id string, rotate bool, mintedToken, prevObsolete string, lastUsed, claimedFrom time.Time) {
	err := rt.storage.UpdateRefreshToken(ctx, id, func(old storage.RefreshToken) (storage.RefreshToken, error) {
		if !old.IsActive() || old.Token != mintedToken || !old.LastUsed.Equal(lastUsed) {
			return old, nil
		}
		if rotate {
			old.Token = old.ObsoleteToken
			old.ObsoleteToken = prevObsolete
		}
		old.LastUsed = claimedFrom
		return old, nil
	})
	if err != nil {
		rt.logger.ErrorContext(ctx, "failed to undo refresh token claim", "err", err)
	}
}

// updateOfflineSession records the refresh token's new last-used time, and any
// updated connector data, on the user's offline session.
func (rt *RefreshStore) updateOfflineSession(ctx context.Context, refresh *storage.RefreshToken, ident connector.Identity, lastUsed time.Time) error {
	offlineSessionUpdater := func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
		ref := old.RefreshTokenRef(refresh.ClientID, refresh.ID)
		if ref == nil {
			return old, errors.New("refresh token invalid")
		}

		if ref.LastUsed.Before(lastUsed) {
			ref.LastUsed = lastUsed
		}
		if len(ident.ConnectorData) > 0 {
			old.ConnectorData = ident.ConnectorData
		}

		rt.logger.DebugContext(ctx, "saved connector data", "user_id", ident.UserID, "connector_data_bytes", len(ident.ConnectorData))
		return old, nil
	}

	if err := rt.storage.UpdateOfflineSessions(ctx, refresh.Claims.UserID, refresh.ConnectorID, offlineSessionUpdater); err != nil {
		rt.logger.ErrorContext(ctx, "failed to update offline session", "err", err)
		return err
	}

	return nil
}

// RevokeClients deletes the refresh tokens issued to the named clients for the
// user/connector pair, in one pass over the offline session. Every other client's
// token is left alone. See RevokeAll for the unscoped variant.
func (rt *RefreshStore) RevokeClients(ctx context.Context, userID, connectorID string, clientIDs []string) {
	if len(clientIDs) == 0 {
		return
	}

	revoking := make(map[string]struct{}, len(clientIDs))
	for _, id := range clientIDs {
		if id != "" {
			revoking[id] = struct{}{}
		}
	}

	rt.revoke(ctx, userID, connectorID, func(id string) bool {
		_, ok := revoking[id]
		return ok
	})
}

// RevokeAll deletes every refresh token for the user/connector pair. This is the
// administrative hammer, reached through the gRPC API when an operator terminates a
// user's sessions or deletes their identity — not something an ordinary RP-initiated
// logout does.
func (rt *RefreshStore) RevokeAll(ctx context.Context, userID, connectorID string) {
	rt.revoke(ctx, userID, connectorID, func(string) bool { return true })
}

// revoke is the best-effort adapter used by logout and administrative session
// termination. API callers use Revoke directly to receive storage errors.
func (rt *RefreshStore) revoke(ctx context.Context, userID, connectorID string, match func(clientID string) bool) {
	_, err := rt.Revoke(ctx, userID, connectorID, func(ref *storage.RefreshTokenRef) bool { return match(ref.ClientID) })
	if err != nil {
		rt.logger.ErrorContext(ctx, "revoke refresh tokens", "err", err)
	}
}

// Revoke removes matching grants at the offline-session transaction's commit.
// Deleting rows is secondary: lookup and rotation both require membership.
// The predicate must be pure because storage can retry the updater.
func (rt *RefreshStore) Revoke(ctx context.Context, userID, connectorID string, match func(*storage.RefreshTokenRef) bool) (int, error) {
	var refs []*storage.RefreshTokenRef
	err := rt.storage.UpdateOfflineSessions(ctx, userID, connectorID, func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
		refs = nil
		for _, ref := range old.RefreshTokenRefs() {
			if match(ref) {
				refs = append(refs, ref)
				old.DeleteRefreshTokenRef(ref.ClientID, ref.ID)
			}
		}
		return old, nil
	})
	if errors.Is(err, storage.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	for _, ref := range refs {
		if err := rt.storage.DeleteRefresh(ctx, ref.ID); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return len(refs), err
		}
	}
	return len(refs), nil
}
