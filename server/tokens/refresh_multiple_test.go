package tokens

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

func decodeRefresh(t *testing.T, raw string) *internal.RefreshToken {
	t.Helper()
	token := new(internal.RefreshToken)
	require.NoError(t, internal.Unmarshal(raw, token))
	return token
}

func TestIndependentRefreshGrants(t *testing.T) {
	ctx := t.Context()
	rt, s := newTestStore(t)
	auth := testAuthorization()
	auth.Client.RefreshTokenLimit = 2
	auth.SessionID = "same-browser"
	first, err := rt.Create(ctx, auth)
	require.NoError(t, err)
	second, err := rt.Create(ctx, auth)
	require.NoError(t, err)
	_, err = rt.Create(ctx, auth)
	require.ErrorIs(t, err, ErrRefreshTokenLimit)
	strategy := NewRefreshStrategy(true, 0, 0, 0, nil)
	for _, raw := range []string{first, second} {
		token := decodeRefresh(t, raw)
		for i := 0; i < 3; i++ {
			row, err := LookupRefreshToken(ctx, s, strategy, rt.logger, &auth.Client.ID, token)
			require.NoError(t, err)
			require.Equal(t, storage.RefreshTokenActive, row.State, "rotation preserves the independent-grant marker")
			require.Equal(t, auth.Claims, row.Claims)
			rotated, ident, err := rt.Rotate(ctx, row, token, strategy, func(context.Context) (connector.Identity, error) { return IdentityFromClaims(auth.Claims), nil })
			require.NoError(t, err)
			require.Equal(t, auth.Claims.UserID, ident.UserID)
			token = decodeRefresh(t, rotated)
		}
	}
	// Lowering the quota never evicts grants.
	auth.Client.RefreshTokenLimit = 1
	_, err = rt.Create(ctx, auth)
	require.ErrorIs(t, err, ErrRefreshTokenLimit)
	session, err := s.GetOfflineSessions(ctx, auth.Claims.UserID, auth.ConnectorID)
	require.NoError(t, err)
	require.Len(t, session.RefreshTokens, 2)
	// Disabling the feature drains existing independent grants while new logins replace.
	auth.Client.RefreshTokenLimit = 0
	legacy1, err := rt.Create(ctx, auth)
	require.NoError(t, err)
	_, err = rt.Create(ctx, auth)
	require.NoError(t, err)
	_, err = s.GetRefresh(ctx, decodeRefresh(t, legacy1).RefreshId)
	require.ErrorIs(t, err, storage.ErrNotFound)
	session, err = s.GetOfflineSessions(ctx, auth.Claims.UserID, auth.ConnectorID)
	require.NoError(t, err)
	require.Len(t, session.RefreshTokens, 2)
	require.Len(t, session.Refresh, 1)
	for _, ref := range session.RefreshTokens {
		row, err := s.GetRefresh(ctx, ref.ID)
		require.NoError(t, err)
		require.Equal(t, storage.RefreshTokenActive, row.State, "disabling new issuance does not change existing grants")
	}
}

func TestIndependentConcurrentFirstLogin(t *testing.T) {
	ctx := t.Context()
	rt, s := newTestStore(t)
	auth := testAuthorization()
	auth.Client.RefreshTokenLimit = 1
	otherReplica := NewRefreshStore(s, time.Now, rt.logger)
	start := make(chan struct{})
	results := make(chan error, 12)
	var wg sync.WaitGroup
	for i := 0; i < cap(results); i++ {
		replica := rt
		if i%2 == 1 {
			replica = otherReplica
		}
		wg.Go(func() { <-start; _, err := replica.Create(ctx, auth); results <- err })
	}
	close(start)
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else {
			require.ErrorIs(t, err, ErrRefreshTokenLimit)
		}
	}
	require.Equal(t, 1, accepted)
	rows, err := s.ListRefreshTokens(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1, "rejected issuance must leave no rows")
}

func TestIndependentExpiryReclaimsCapacity(t *testing.T) {
	for _, absolute := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "absolute"}[absolute], func(t *testing.T) {
			ctx := t.Context()
			now := time.Now()
			clock := func() time.Time { return now }
			rt, s := newTestStore(t)
			rt.now = clock
			if absolute {
				rt.strategy = NewRefreshStrategy(true, time.Hour, 0, 0, clock)
			} else {
				rt.strategy = NewRefreshStrategy(true, 0, time.Hour, 0, clock)
			}
			auth := testAuthorization()
			auth.Client.RefreshTokenLimit = 1
			raw, err := rt.Create(ctx, auth)
			require.NoError(t, err)
			now = now.Add(2 * time.Hour)
			_, err = rt.Create(ctx, auth)
			require.NoError(t, err)
			_, err = s.GetRefresh(ctx, decodeRefresh(t, raw).RefreshId)
			require.ErrorIs(t, err, storage.ErrNotFound)
		})
	}
}

type issuanceFailureStorage struct {
	storage.Storage
	failRegister bool
	failActivate bool
	failDelete   bool
}

var errIssuance = errors.New("injected issuance failure")

func (s *issuanceFailureStorage) UpdateOfflineSessions(ctx context.Context, user, conn string, update func(storage.OfflineSessions) (storage.OfflineSessions, error)) error {
	if s.failRegister {
		return errIssuance
	}
	return s.Storage.UpdateOfflineSessions(ctx, user, conn, update)
}

func (s *issuanceFailureStorage) UpdateRefreshToken(ctx context.Context, id string, update func(storage.RefreshToken) (storage.RefreshToken, error)) error {
	if s.failActivate {
		return errIssuance
	}
	return s.Storage.UpdateRefreshToken(ctx, id, update)
}

func (s *issuanceFailureStorage) DeleteRefresh(ctx context.Context, id string) error {
	if s.failDelete {
		return errIssuance
	}
	return s.Storage.DeleteRefresh(ctx, id)
}

func TestIndependentFailedIssuanceIsInactive(t *testing.T) {
	for _, register := range []bool{false, true} {
		t.Run(map[bool]string{true: "registration", false: "activation"}[register], func(t *testing.T) {
			ctx := t.Context()
			logger := slog.New(slog.DiscardHandler)
			base := memory.New(logger)
			s := &issuanceFailureStorage{Storage: base, failRegister: register, failActivate: !register, failDelete: true}
			rt := NewRefreshStore(s, time.Now, logger)
			auth := testAuthorization()
			auth.Client.RefreshTokenLimit = 1
			_, err := rt.Create(ctx, auth)
			require.ErrorIs(t, err, errIssuance)
			rows, err := base.ListRefreshTokens(ctx)
			require.NoError(t, err)
			require.Len(t, rows, 1)
			row := rows[0]
			_, err = LookupRefreshToken(ctx, base, rt.strategy, logger, nil, &internal.RefreshToken{RefreshId: row.ID, Token: row.Token})
			require.ErrorIs(t, err, ErrRefreshTokenInvalid)
			// The abandoned row does not consume quota once storage recovers.
			restarted := NewRefreshStore(base, time.Now, logger)
			_, err = restarted.Create(ctx, auth)
			require.NoError(t, err)
		})
	}
}

func TestLegacyRollbackPreservesTokenAfterActivationFailure(t *testing.T) {
	ctx := t.Context()
	rt, s := newTestStore(t)
	auth := testAuthorization()
	first, err := rt.Create(ctx, auth)
	require.NoError(t, err)
	previous := decodeRefresh(t, first)
	replacement := NewRefreshStore(&issuanceFailureStorage{Storage: s, failActivate: true}, rt.now, rt.logger)
	_, err = replacement.Create(ctx, auth)
	require.ErrorIs(t, err, errIssuance)
	_, err = LookupRefreshToken(ctx, s, rt.strategy, rt.logger, nil, previous)
	require.NoError(t, err, "rollback must restore a working credential, not only its reference")
}

func TestRefreshPruneDoesNotDeleteAdvancedRow(t *testing.T) {
	ctx := t.Context()
	rt, s := newTestStore(t)
	now := time.Now()
	rt.now = func() time.Time { return now }
	rt.strategy = NewRefreshStrategy(true, 0, time.Hour, 0, rt.now)
	auth := testAuthorization()
	auth.Client.RefreshTokenLimit = 1
	raw, err := rt.Create(ctx, auth)
	require.NoError(t, err)
	token := decodeRefresh(t, raw)
	stale, err := s.GetRefresh(ctx, token.RefreshId)
	require.NoError(t, err)
	now = now.Add(2 * time.Hour)
	// Simulate a refresh whose row committed before its offline-session update.
	require.NoError(t, s.UpdateRefreshToken(ctx, token.RefreshId, func(row storage.RefreshToken) (storage.RefreshToken, error) { row.LastUsed = now; return row, nil }))
	require.NoError(t, rt.collect(ctx, stale))
	_, err = s.GetRefresh(ctx, token.RefreshId)
	require.NoError(t, err)
	_, err = rt.Create(ctx, auth)
	require.ErrorIs(t, err, ErrRefreshTokenLimit)
}

func TestRefreshOrphanAndRevokeFailureAreInactive(t *testing.T) {
	ctx := t.Context()
	rt, s := newTestStore(t)
	auth := testAuthorization()
	auth.Client.RefreshTokenLimit = 2
	first, err := rt.Create(ctx, auth)
	require.NoError(t, err)
	second, err := rt.Create(ctx, auth)
	require.NoError(t, err)
	rt.storage = &issuanceFailureStorage{Storage: s, failDelete: true}
	one := decodeRefresh(t, first)
	n, err := rt.Revoke(ctx, auth.Claims.UserID, auth.ConnectorID, func(ref *storage.RefreshTokenRef) bool { return ref.ID == one.RefreshId })
	require.Equal(t, 1, n)
	require.ErrorIs(t, err, errIssuance)
	_, err = LookupRefreshToken(ctx, s, rt.strategy, rt.logger, nil, one)
	require.ErrorIs(t, err, ErrRefreshTokenInvalid)
	_, err = LookupRefreshToken(ctx, s, rt.strategy, rt.logger, nil, decodeRefresh(t, second))
	require.NoError(t, err)
	rt.storage = s
	_, err = rt.Create(ctx, auth)
	require.NoError(t, err)
}

type pausedActivation struct {
	storage.Storage
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (s *pausedActivation) UpdateRefreshToken(ctx context.Context, id string, update func(storage.RefreshToken) (storage.RefreshToken, error)) error {
	s.once.Do(func() {
		close(s.entered)
		select {
		case <-s.resume:
		case <-ctx.Done():
		}
	})
	return s.Storage.UpdateRefreshToken(ctx, id, update)
}

func awaitRefreshStep(t *testing.T, step <-chan struct{}) {
	t.Helper()
	select {
	case <-step:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for refresh step")
	}
}

func TestPendingIssuanceCannotReviveAfterPrune(t *testing.T) {
	ctx := t.Context()
	rt, base := newTestStore(t)
	now := time.Now()
	rt.now = func() time.Time { return now }
	paused := &pausedActivation{Storage: base, entered: make(chan struct{}), resume: make(chan struct{})}
	rt.storage = paused
	auth := testAuthorization()
	auth.Client.RefreshTokenLimit = 1
	result := make(chan error, 1)
	go func() { _, err := rt.Create(ctx, auth); result <- err }()
	awaitRefreshStep(t, paused.entered)
	collector := NewRefreshStore(base, func() time.Time { return now.Add(2 * refreshRegistrationTimeout) }, rt.logger)
	require.NoError(t, collector.prune(ctx, auth.Claims.UserID, auth.ConnectorID, auth.Client.ID))
	close(paused.resume)
	require.Error(t, <-result)
	rows, err := base.ListRefreshTokens(ctx)
	require.NoError(t, err)
	require.Empty(t, rows)
	_, err = collector.Create(ctx, auth)
	require.NoError(t, err)
}

func TestIndependentRevokeWhileResolvingIdentity(t *testing.T) {
	ctx := t.Context()
	rt, s := newTestStore(t)
	auth := testAuthorization()
	auth.Client.RefreshTokenLimit = 2
	first, err := rt.Create(ctx, auth)
	require.NoError(t, err)
	second, err := rt.Create(ctx, auth)
	require.NoError(t, err)
	token := decodeRefresh(t, first)
	row, err := s.GetRefresh(ctx, token.RefreshId)
	require.NoError(t, err)
	entered, resume := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, _, err := rt.Rotate(ctx, &row, token, rt.strategy, func(context.Context) (connector.Identity, error) {
			close(entered)
			<-resume
			return IdentityFromClaims(auth.Claims), nil
		})
		result <- err
	}()
	awaitRefreshStep(t, entered)
	_, err = rt.Revoke(ctx, auth.Claims.UserID, auth.ConnectorID, func(ref *storage.RefreshTokenRef) bool { return ref.ID == token.RefreshId })
	require.NoError(t, err)
	close(resume)
	require.Error(t, <-result)
	_, err = LookupRefreshToken(ctx, s, rt.strategy, rt.logger, nil, token)
	require.ErrorIs(t, err, ErrRefreshTokenInvalid)
	_, err = LookupRefreshToken(ctx, s, rt.strategy, rt.logger, nil, decodeRefresh(t, second))
	require.NoError(t, err)
}

type createFailureStorage struct {
	storage.Storage
	row bool
}

func (s createFailureStorage) CreateRefresh(ctx context.Context, row storage.RefreshToken) error {
	if s.row {
		return errIssuance
	}
	return s.Storage.CreateRefresh(ctx, row)
}

func (s createFailureStorage) CreateOfflineSessions(ctx context.Context, session storage.OfflineSessions) error {
	return errIssuance
}

func TestIndependentInitialWriteFailures(t *testing.T) {
	for _, row := range []bool{false, true} {
		t.Run(map[bool]string{false: "session", true: "row"}[row], func(t *testing.T) {
			rt, s := newTestStore(t)
			rt.storage = createFailureStorage{Storage: s, row: row}
			auth := testAuthorization()
			auth.Client.RefreshTokenLimit = 1
			_, err := rt.Create(t.Context(), auth)
			require.ErrorIs(t, err, errIssuance)
			rows, err := s.ListRefreshTokens(t.Context())
			require.NoError(t, err)
			require.Empty(t, rows)
		})
	}
}

type repeatedOfflineUpdater struct{ storage.Storage }

func (s repeatedOfflineUpdater) UpdateOfflineSessions(ctx context.Context, user, conn string, update func(storage.OfflineSessions) (storage.OfflineSessions, error)) error {
	return s.Storage.UpdateOfflineSessions(ctx, user, conn, func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
		// Discard an attempted update as a backend would on a transaction conflict.
		if _, err := update(old.Clone()); err != nil {
			return old, err
		}
		return update(old.Clone())
	})
}

func TestIndependentRegistrationUpdaterMayRepeat(t *testing.T) {
	rt, s := newTestStore(t)
	rt.storage = repeatedOfflineUpdater{Storage: s}
	auth := testAuthorization()
	auth.Client.RefreshTokenLimit = 2
	for i := 0; i < 2; i++ {
		_, err := rt.Create(t.Context(), auth)
		require.NoError(t, err)
	}
	_, err := rt.Create(t.Context(), auth)
	require.ErrorIs(t, err, ErrRefreshTokenLimit)
	rows, err := s.ListRefreshTokens(t.Context())
	require.NoError(t, err)
	require.Len(t, rows, 2)
}
