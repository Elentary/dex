package tokens

import (
	"context"
	"errors"
	"time"

	"github.com/dexidp/dex/storage"
)

// A registration interrupted for this long is abandoned. Activation and GC
// compete on the row's state, so even a paused process cannot revive it later.
const refreshRegistrationTimeout = 5 * time.Minute

func (rt *RefreshStore) expired(row storage.RefreshToken) bool {
	switch row.State {
	case storage.RefreshTokenRevoked:
		return true
	case storage.RefreshTokenPending:
		return !rt.now().Before(row.CreatedAt.Add(refreshRegistrationTimeout))
	default:
		return rt.strategy.CompletelyExpired(row.CreatedAt) || rt.strategy.ExpiredBecauseUnused(row.LastUsed)
	}
}

// prune only visits this user's indexed grants, never the global token table.
func (rt *RefreshStore) prune(ctx context.Context, userID, connectorID, clientID string) error {
	session, err := rt.storage.GetOfflineSessions(ctx, userID, connectorID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, ref := range session.RefreshTokenRefs() {
		if ref.ClientID != clientID {
			continue
		}
		row, err := rt.storage.GetRefresh(ctx, ref.ID)
		if errors.Is(err, storage.ErrNotFound) {
			if err := rt.detach(ctx, userID, connectorID, ref.ClientID, ref.ID); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if rt.expired(row) {
			if err := rt.collect(ctx, row, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func (rt *RefreshStore) detach(ctx context.Context, userID, connectorID, clientID, id string) error {
	err := rt.storage.UpdateOfflineSessions(ctx, userID, connectorID, func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
		old.DeleteRefreshTokenRef(clientID, id)
		return old, nil
	})
	if errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	return err
}

// collect first tombstones the live row atomically. In particular, a LastUsed
// copied from the offline-session index is never evidence of expiry: rotation
// may already have advanced the row while that index is still being updated.
func (rt *RefreshStore) collect(ctx context.Context, snapshot storage.RefreshToken, orphan bool) error {
	tombstoned := false
	err := rt.storage.UpdateRefreshToken(ctx, snapshot.ID, func(old storage.RefreshToken) (storage.RefreshToken, error) {
		tombstoned = false
		// Only independent grants have monotonic index membership after activation.
		// A missing legacy reference may still be registered by an old replica or
		// restored by rollback. Absence alone cannot authorize deleting that row.
		abandoned := orphan && old.State == storage.RefreshTokenActive && snapshot.State == storage.RefreshTokenActive && old.Token == snapshot.Token && old.LastUsed.Equal(snapshot.LastUsed)
		if !abandoned && !rt.expired(old) {
			return old, nil
		}
		old.State = storage.RefreshTokenRevoked
		old.Token, old.ObsoleteToken = "", ""
		tombstoned = true
		return old, nil
	})
	if errors.Is(err, storage.ErrNotFound) {
		return rt.detach(ctx, snapshot.Claims.UserID, snapshot.ConnectorID, snapshot.ClientID, snapshot.ID)
	}
	if err != nil || !tombstoned {
		return err
	}
	if err := rt.detach(ctx, snapshot.Claims.UserID, snapshot.ConnectorID, snapshot.ClientID, snapshot.ID); err != nil {
		return err
	}
	err = rt.storage.DeleteRefresh(ctx, snapshot.ID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	return err
}

// GarbageCollect sweeps bounded pages. It is safe to run on multiple replicas;
// every deletion rechecks the current row in an atomic updater. Missing rows
// and indexes after a crash or partial write are harmless to token validation.
func (rt *RefreshStore) GarbageCollect(ctx context.Context) error {
	cursor := ""
	for {
		rows, next, err := rt.storage.ListRefreshTokensPage(ctx, cursor, 100)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			orphan := false
			if !rt.expired(row) {
				// Legacy rows and pending registrations cannot be identified as
				// abandoned from the index. Avoid a membership read for them.
				if row.State != storage.RefreshTokenActive {
					continue
				}
				session, err := rt.storage.GetOfflineSessions(ctx, row.Claims.UserID, row.ConnectorID)
				if err != nil && !errors.Is(err, storage.ErrNotFound) {
					return err
				}
				orphan = errors.Is(err, storage.ErrNotFound) || session.RefreshTokenRef(row.ClientID, row.ID) == nil
				if !orphan {
					continue
				}
			}
			if err := rt.collect(ctx, row, orphan); err != nil {
				return err
			}
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}
