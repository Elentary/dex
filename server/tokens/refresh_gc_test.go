package tokens

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
)

func TestRefreshGCPreservesUnregisteredLegacyToken(t *testing.T) {
	ctx := t.Context()
	rt, s := newTestStore(t)
	auth := testAuthorization()
	// v2.46.1 writes a row with no State, then registers it separately. Run the
	// upgraded replica's collector in that gap, before the old issuer returns.
	row := storage.RefreshToken{
		ID: storage.NewID(), Token: storage.NewID(), ClientID: auth.Client.ID,
		ConnectorID: auth.ConnectorID, Claims: auth.Claims, CreatedAt: rt.now(), LastUsed: rt.now(),
	}
	require.NoError(t, s.CreateRefresh(ctx, row))
	require.NoError(t, rt.GarbageCollect(ctx))
	_, err := s.GetRefresh(ctx, row.ID)
	require.NoError(t, err, "GC must not delete an old replica's in-flight issuance")
	require.NoError(t, s.CreateOfflineSessions(ctx, storage.OfflineSessions{
		UserID: row.Claims.UserID, ConnID: row.ConnectorID,
		Refresh: map[string]*storage.RefreshTokenRef{row.ClientID: {ID: row.ID, ClientID: row.ClientID}},
	}))
	_, err = LookupRefreshToken(ctx, s, rt.strategy, rt.logger, nil, &internal.RefreshToken{RefreshId: row.ID, Token: row.Token})
	require.NoError(t, err, "the token returned by the old replica must be usable")
}

type collectBeforeActivationFailure struct {
	storage.Storage
	collector *RefreshStore
}

func (s collectBeforeActivationFailure) UpdateRefreshToken(ctx context.Context, id string, update func(storage.RefreshToken) (storage.RefreshToken, error)) error {
	row, err := s.Storage.GetRefresh(ctx, id)
	if err != nil {
		return err
	}
	if row.State == storage.RefreshTokenPending {
		// The replacement reference has committed, temporarily hiding the old
		// grant. A second replica collects before this issuer fails activation.
		if err := s.collector.GarbageCollect(ctx); err != nil {
			return err
		}
		return errIssuance
	}
	return s.Storage.UpdateRefreshToken(ctx, id, update)
}

func TestLegacyRollbackPreservesTokenDuringGC(t *testing.T) {
	ctx := t.Context()
	rt, s := newTestStore(t)
	auth := testAuthorization()
	rt.now = func() time.Time { return time.Now().Add(-24 * time.Hour) }
	first, err := rt.Create(ctx, auth)
	require.NoError(t, err)
	rt.now = time.Now
	previous := decodeRefresh(t, first)
	replacement := NewRefreshStore(collectBeforeActivationFailure{Storage: s, collector: rt}, rt.now, rt.logger)
	_, err = replacement.Create(ctx, auth)
	require.ErrorIs(t, err, errIssuance)
	_, err = LookupRefreshToken(ctx, s, rt.strategy, rt.logger, nil, previous)
	require.NoError(t, err, "rollback must restore a working credential, not only its reference")
}

type offlineReadCounter struct {
	storage.Storage
	reads int
}

func (s *offlineReadCounter) GetOfflineSessions(ctx context.Context, userID, connectorID string) (storage.OfflineSessions, error) {
	s.reads++
	return s.Storage.GetOfflineSessions(ctx, userID, connectorID)
}

func TestRefreshGCSkipsHealthyLegacySessionReads(t *testing.T) {
	rt, s := newTestStore(t)
	auth := testAuthorization()
	_, err := rt.Create(t.Context(), auth)
	require.NoError(t, err)
	counted := &offlineReadCounter{Storage: s}
	collector := NewRefreshStore(counted, rt.now, rt.logger)
	require.NoError(t, collector.GarbageCollect(t.Context()))
	require.Zero(t, counted.reads, "a healthy legacy row needs no membership query")
}

func TestRefreshGCStillExpiresLegacyRows(t *testing.T) {
	ctx := t.Context()
	rt, s := newTestStore(t)
	now := time.Now()
	rt.now = func() time.Time { return now }
	rt.strategy = NewRefreshStrategy(true, time.Hour, 0, 0, rt.now)
	auth := testAuthorization()
	raw, err := rt.Create(ctx, auth)
	require.NoError(t, err)
	token := decodeRefresh(t, raw)
	now = now.Add(2 * time.Hour)
	require.NoError(t, rt.GarbageCollect(ctx))
	_, err = s.GetRefresh(ctx, token.RefreshId)
	require.ErrorIs(t, err, storage.ErrNotFound)
	session, err := s.GetOfflineSessions(ctx, auth.Claims.UserID, auth.ConnectorID)
	require.NoError(t, err)
	require.Nil(t, session.RefreshTokenRef(auth.Client.ID, token.RefreshId))
}
