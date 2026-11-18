package conformance

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/storage"
)

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
