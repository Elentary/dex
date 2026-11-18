package tokens

import (
	"context"
	"errors"

	"github.com/dexidp/dex/storage"
)

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
