package conformance

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/storage"
)

func testRefreshTokenPages(t *testing.T, s storage.Storage) {
	ctx := t.Context()
	want := map[string]bool{}
	for i := 0; i < 7; i++ {
		id := storage.NewID()
		want[id] = true
		require.NoError(t, s.CreateRefresh(ctx, storage.RefreshToken{ID: id, ClientID: "client", ConnectorID: "connector", Nonce: "nonce", Token: "secret", State: storage.RefreshTokenPending, CreatedAt: time.Now(), LastUsed: time.Now(), Claims: storage.Claims{UserID: "user", Username: "user", Email: "user@example.com"}}))
	}
	seen := map[string]bool{}
	cursor := ""
	for page := 0; ; page++ {
		require.Less(t, page, 20, "cursor must make progress")
		rows, next, err := s.ListRefreshTokensPage(ctx, cursor, 2)
		require.NoError(t, err)
		require.LessOrEqual(t, len(rows), 2)
		for _, row := range rows {
			require.False(t, seen[row.ID], "duplicate across pages")
			seen[row.ID] = true
			if want[row.ID] {
				require.Equal(t, storage.RefreshTokenPending, row.State)
				require.NoError(t, s.DeleteRefresh(ctx, row.ID)) // deletion must not shift the next page
			}
		}
		if next == "" {
			break
		}
		require.NotEqual(t, cursor, next)
		cursor = next
	}
	for id := range want {
		require.True(t, seen[id])
	}
}

func testIndependentRefreshAdmission(t *testing.T, s storage.Storage) {
	ctx := t.Context()
	user, conn := storage.NewID(), "connector"
	require.NoError(t, s.CreateOfflineSessions(ctx, storage.OfflineSessions{UserID: user, ConnID: conn, Refresh: map[string]*storage.RefreshTokenRef{}}))
	defer s.DeleteOfflineSessions(ctx, user, conn)
	full := errors.New("full")
	const racers = 6
	results := make(chan error, racers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Go(func() {
			<-start
			id := storage.NewID()
			results <- s.UpdateOfflineSessions(ctx, user, conn, func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
				if len(old.RefreshTokens) != 0 {
					return old, full
				}
				old.RefreshTokens = map[string]*storage.RefreshTokenRef{id: {ID: id, ClientID: "client"}}
				return old, nil
			})
		})
	}
	close(start)
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else {
			require.ErrorIs(t, err, full)
		}
	}
	require.Equal(t, 1, accepted, "only one concurrent transaction may take the final slot")
	session, err := s.GetOfflineSessions(ctx, user, conn)
	require.NoError(t, err)
	require.Len(t, session.RefreshTokens, 1)
	// An aborted callback must not leak map mutations from a failed transaction.
	require.ErrorIs(t, s.UpdateOfflineSessions(ctx, user, conn, func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
		for id := range old.RefreshTokens {
			delete(old.RefreshTokens, id)
		}
		return old, full
	}), full)
	session, err = s.GetOfflineSessions(ctx, user, conn)
	require.NoError(t, err)
	require.Len(t, session.RefreshTokens, 1)
}
