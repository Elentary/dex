package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/api/v2"
	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

func TestIndependentRefreshGrantLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	httpServer, s := newTestServer(ctx, t, nil)
	defer httpServer.Close()
	client := storage.Client{ID: "kubernetes", Secret: "mock-client-secret", RedirectURIs: []string{"http://localhost/callback"}}
	require.NoError(t, s.storage.CreateClient(ctx, client))
	provider, err := oidc.NewProvider(ctx, httpServer.URL)
	require.NoError(t, err)
	verifier := provider.Verifier(&oidc.Config{ClientID: client.ID})

	postToken := func(form url.Values) *httptest.ResponseRecorder {
		request := httptest.NewRequestWithContext(ctx, http.MethodPost, s.issuerURL.String()+"/token", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.SetBasicAuth(client.ID, client.Secret)
		recorder := httptest.NewRecorder()
		s.ServeHTTP(recorder, request)
		return recorder
	}
	newCode := func(scopes ...string) string {
		code := storage.AuthCode{
			ID: storage.NewID(), ClientID: client.ID, ConnectorID: "mock",
			Claims: storage.Claims{UserID: "same-user"}, Scopes: scopes,
			RedirectURI: client.RedirectURIs[0], Expiry: s.now().Add(time.Minute),
		}
		require.NoError(t, s.storage.CreateAuthCode(ctx, code))
		return code.ID
	}
	exchange := func(code string) *httptest.ResponseRecorder {
		return postToken(url.Values{"grant_type": {grantTypeAuthorizationCode}, "code": {code}, "redirect_uri": client.RedirectURIs})
	}
	rotate := func(raw string) *httptest.ResponseRecorder {
		return postToken(url.Values{"grant_type": {grantTypeRefreshToken}, "refresh_token": {raw}})
	}
	decode := func(response *httptest.ResponseRecorder) accessTokenResponse {
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		var result accessTokenResponse
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
		return result
	}
	login := func() accessTokenResponse {
		return decode(exchange(newCode(scopeOpenID, scopeOfflineAccess)))
	}

	legacy := login()
	s.refreshTokenLimits = map[string]uint32{client.ID: 3}
	a, b := login(), login()
	legacyID, err := verifier.Verify(ctx, legacy.IDToken)
	require.NoError(t, err)
	for _, issued := range []accessTokenResponse{a, b} {
		verified, err := verifier.Verify(ctx, issued.IDToken)
		require.NoError(t, err)
		require.Equal(t, legacyID.Subject, verified.Subject)
	}
	require.NotEqual(t, a.RefreshToken, b.RefreshToken)

	denied := exchange(newCode(scopeOpenID, scopeOfflineAccess))
	require.Equal(t, http.StatusBadRequest, denied.Code)
	require.Contains(t, denied.Body.String(), errInvalidGrant)
	require.Contains(t, denied.Body.String(), "Refresh token limit reached")
	require.NotContains(t, denied.Body.String(), `"id_token"`)
	require.Empty(t, decode(exchange(newCode(scopeOpenID))).RefreshToken)

	// A device flow that hits the same cap gets a terminal polling response.
	deviceReq := storage.DeviceRequest{
		UserCode: "TEST-CODE", DeviceCode: storage.NewDeviceCode(), ClientID: client.ID, ClientSecret: client.Secret,
		Expiry: s.now().Add(time.Minute),
	}
	require.NoError(t, s.storage.CreateDeviceRequest(ctx, deviceReq))
	require.NoError(t, s.storage.CreateDeviceToken(ctx, storage.DeviceToken{
		DeviceCode: deviceReq.DeviceCode, Status: deviceTokenPending, Expiry: deviceReq.Expiry,
	}))
	query := url.Values{"state": {deviceReq.UserCode}, "code": {newCode(scopeOpenID, scopeOfflineAccess)}}
	callback := httptest.NewRequestWithContext(ctx, http.MethodGet, s.issuerURL.String()+deviceCallbackURI+"?"+query.Encode(), nil)
	denied = httptest.NewRecorder()
	s.ServeHTTP(denied, callback)
	require.Equal(t, http.StatusBadRequest, denied.Code)
	poll := httptest.NewRequestWithContext(ctx, http.MethodPost, s.issuerURL.String()+"/device/token", nil)
	poll.Form = url.Values{"device_code": {deviceReq.DeviceCode}}
	denied = httptest.NewRecorder()
	s.handleDeviceToken(denied, poll)
	require.Equal(t, http.StatusBadRequest, denied.Code)
	require.Contains(t, denied.Body.String(), errAccessDenied)

	// Two devices rotate different grants even when the requests overlap.
	rotationA := make(chan *httptest.ResponseRecorder, 1)
	go func() { rotationA <- rotate(a.RefreshToken) }()
	newB := decode(rotate(b.RefreshToken))
	newA := decode(<-rotationA)
	require.NotEqual(t, a.RefreshToken, newA.RefreshToken)
	require.NotEqual(t, b.RefreshToken, newB.RefreshToken)
	decode(rotate(legacy.RefreshToken))

	admin := newAPI(s.storage, s.logger, t)
	defer admin.Close()
	failingAdmin := newAPI(keepRefreshRows{s.storage}, s.logger, t)
	defer failingAdmin.Close()
	version, err := admin.GetVersion(ctx, &api.VersionReq{})
	require.NoError(t, err)
	require.EqualValues(t, 3, version.Api)
	list, err := admin.ListRefresh(ctx, &api.ListRefreshReq{UserId: legacyID.Subject})
	require.NoError(t, err)
	require.Len(t, list.RefreshTokens, 3)
	var token internal.RefreshToken
	require.NoError(t, internal.Unmarshal(newA.RefreshToken, &token))
	wrongClient, err := admin.RevokeRefreshToken(ctx, &api.RevokeRefreshTokenReq{
		UserId: legacyID.Subject, ClientId: "another-client", RefreshTokenId: token.RefreshId,
	})
	require.NoError(t, err)
	require.True(t, wrongClient.NotFound)
	revokeRequest := &api.RevokeRefreshTokenReq{
		UserId: legacyID.Subject, ClientId: client.ID, RefreshTokenId: token.RefreshId,
	}
	_, err = failingAdmin.RevokeRefreshToken(ctx, revokeRequest)
	require.Error(t, err)
	stillPresent, err := s.storage.GetRefresh(ctx, token.RefreshId)
	require.NoError(t, err)
	require.Equal(t, token.Token, stillPresent.Token)
	session, err := s.storage.GetOfflineSessions(ctx, "same-user", "mock")
	require.NoError(t, err)
	require.NotNil(t, session.Refresh[client.ID].Find(token.RefreshId))

	revoked, err := admin.RevokeRefreshToken(ctx, revokeRequest)
	require.NoError(t, err)
	require.False(t, revoked.NotFound)
	_, err = s.storage.GetRefresh(ctx, token.RefreshId)
	require.ErrorIs(t, err, storage.ErrNotFound)
	require.Equal(t, http.StatusBadRequest, rotate(newA.RefreshToken).Code)
	_, err = s.introspectRefreshToken(ctx, newA.RefreshToken)
	require.Error(t, err)

	// Issuance returns to legacy mode while a previously issued grant remains usable.
	delete(s.refreshTokenLimits, client.ID)
	newLegacy := login()
	newB = decode(rotate(newB.RefreshToken))
	all, err := admin.RevokeRefresh(ctx, &api.RevokeRefreshReq{UserId: legacyID.Subject, ClientId: client.ID})
	require.NoError(t, err)
	require.False(t, all.NotFound)
	require.Equal(t, http.StatusBadRequest, rotate(newB.RefreshToken).Code)
	require.Equal(t, http.StatusBadRequest, rotate(newLegacy.RefreshToken).Code)
}

type keepRefreshRows struct{ storage.Storage }

func (keepRefreshRows) DeleteRefresh(context.Context, string) error {
	return errors.New("token deletion unavailable")
}

func TestIndependentRefreshGrantQuotaAndExpiry(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	clock := func() time.Time { return now }
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &Server{
		storage: memory.New(logger), now: clock, logger: logger,
		refreshTokenPolicy: &RefreshTokenPolicy{now: clock, validIfNotUsedFor: time.Minute},
		refreshTokenLimits: map[string]uint32{"kubernetes": 2},
	}
	grant := storage.RefreshToken{ClientID: "kubernetes", ConnectorID: "mock", Claims: storage.Claims{UserID: "same-user"}}
	const attempts = 8
	start := make(chan struct{})
	results := make(chan error, attempts)
	for range attempts {
		go func() {
			<-start
			_, err := s.issueRefreshToken(ctx, grant, nil)
			results <- err
		}()
	}
	close(start)
	var admitted int
	for range attempts {
		if err := <-results; err == nil {
			admitted++
		} else {
			require.ErrorIs(t, err, errRefreshTokenLimit)
		}
	}
	require.Equal(t, 2, admitted)
	rows, err := s.storage.ListRefreshTokens(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 2)

	now = now.Add(2 * time.Minute)
	_, err = s.issueRefreshToken(ctx, grant, nil)
	require.NoError(t, err)
	rows, err = s.storage.ListRefreshTokens(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
}

type devicePublishFailure struct {
	storage.Storage
	committed bool
}

func (s devicePublishFailure) UpdateDeviceToken(ctx context.Context, code string, update func(storage.DeviceToken) (storage.DeviceToken, error)) error {
	if s.committed {
		if err := s.Storage.UpdateDeviceToken(ctx, code, update); err != nil {
			return err
		}
	}
	return errors.New("device token write acknowledgement failed")
}

func TestDevicePublishFailureDoesNotStrandGrant(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprintf("committed=%t", committed), func(t *testing.T) {
			ctx := context.Background()
			web, s := newTestServer(ctx, t, nil)
			defer web.Close()
			s.storage = devicePublishFailure{Storage: s.storage, committed: committed}
			s.refreshTokenLimits = map[string]uint32{"device-client": 1}
			client := storage.Client{ID: "device-client", Secret: "secret", Name: "device client", RedirectURIs: []string{deviceCallbackURI}}
			require.NoError(t, s.storage.CreateClient(ctx, client))
			require.NoError(t, s.storage.CreateAuthCode(ctx, storage.AuthCode{
				ID: "device-auth-code", ClientID: client.ID, ConnectorID: "mock", RedirectURI: deviceCallbackURI,
				Claims: storage.Claims{UserID: "device-user"}, Scopes: []string{scopeOpenID, scopeOfflineAccess},
				Expiry: s.now().Add(time.Minute),
			}))
			require.NoError(t, s.storage.CreateDeviceRequest(ctx, storage.DeviceRequest{
				UserCode: "device-user-code", DeviceCode: "device-code", ClientID: client.ID,
				ClientSecret: client.Secret, Expiry: s.now().Add(time.Minute),
			}))
			require.NoError(t, s.storage.CreateDeviceToken(ctx, storage.DeviceToken{
				DeviceCode: "device-code", Status: deviceTokenPending, Expiry: s.now().Add(time.Minute),
			}))

			uri := s.issuerURL.String() + deviceCallbackURI + "?" + url.Values{
				"state": {"device-user-code"}, "code": {"device-auth-code"},
			}.Encode()
			recorder := httptest.NewRecorder()
			s.ServeHTTP(recorder, httptest.NewRequestWithContext(ctx, http.MethodGet, uri, nil))
			require.NotEqual(t, http.StatusOK, recorder.Code)

			device, err := s.storage.GetDeviceToken(ctx, "device-code")
			require.NoError(t, err)
			session, err := s.storage.GetOfflineSessions(ctx, "device-user", "mock")
			require.NoError(t, err)
			require.Len(t, session.Refresh[client.ID].Independent, 1)
			for _, ref := range session.Refresh[client.ID].Independent {
				require.Equal(t, device.DeviceCode, ref.DeviceCode)
				require.False(t, ref.PendingUntil.IsZero())
			}
			if committed {
				require.Equal(t, deviceTokenComplete, device.Status)
				var published accessTokenResponse
				require.NoError(t, json.Unmarshal([]byte(device.Token), &published))
				require.NotEmpty(t, published.RefreshToken)
				var pending internal.RefreshToken
				require.NoError(t, internal.Unmarshal(published.RefreshToken, &pending))
				_, invalid := s.getRefreshTokenFromStorage(ctx, &client.ID, &pending)
				require.ErrorIs(t, invalid, invalidErr)
				poll := httptest.NewRequestWithContext(ctx, http.MethodPost, s.issuerURL.String()+"/device/token", nil)
				poll.Form = url.Values{"device_code": {"device-code"}}
				result := httptest.NewRecorder()
				s.handleDeviceToken(result, poll)
				require.Equal(t, http.StatusOK, result.Code, result.Body.String())
				require.Contains(t, result.Body.String(), published.RefreshToken)
				session, err = s.storage.GetOfflineSessions(ctx, "device-user", "mock")
				require.NoError(t, err)
				require.True(t, session.Refresh[client.ID].Find(pending.RefreshId).PendingUntil.IsZero())
				s.now = func() time.Time { return device.Expiry.Add(time.Second) }
				_, err := s.issueRefreshToken(ctx, storage.RefreshToken{
					ClientID: client.ID, ConnectorID: "mock", Claims: storage.Claims{UserID: "device-user"},
				}, nil)
				require.ErrorIs(t, err, errRefreshTokenLimit)
			} else {
				require.Equal(t, deviceTokenPending, device.Status)
				_, err := s.issueRefreshToken(ctx, storage.RefreshToken{
					ClientID: client.ID, ConnectorID: "mock", Claims: storage.Claims{UserID: "device-user"},
				}, nil)
				require.ErrorIs(t, err, errRefreshTokenLimit)
				s.now = func() time.Time { return device.Expiry.Add(time.Second) }
				_, err = s.issueRefreshToken(ctx, storage.RefreshToken{
					ClientID: client.ID, ConnectorID: "mock", Claims: storage.Claims{UserID: "device-user"},
				}, nil)
				require.NoError(t, err)
			}
		})
	}
}

type registrationFailure struct {
	storage.Storage
	committed bool
}

func (s registrationFailure) UpdateOfflineSessions(ctx context.Context, userID, connID string, update func(storage.OfflineSessions) (storage.OfflineSessions, error)) error {
	if s.committed {
		if err := s.Storage.UpdateOfflineSessions(ctx, userID, connID, update); err != nil {
			return err
		}
	}
	return errors.New("offline session write acknowledgement failed")
}

func TestRegistrationFailureCleansOnlyUnregisteredRow(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprintf("committed=%t", committed), func(t *testing.T) {
			ctx := context.Background()
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			base := memory.New(logger)
			require.NoError(t, base.CreateOfflineSessions(ctx, storage.OfflineSessions{
				UserID: "user", ConnID: "mock", Refresh: make(map[string]*storage.RefreshTokenRef),
			}))
			store := registrationFailure{Storage: base, committed: committed}
			now := time.Now().UTC()
			s := &Server{
				storage: store, now: func() time.Time { return now }, logger: logger,
				refreshTokenPolicy: &RefreshTokenPolicy{now: func() time.Time { return now }},
			}
			raw, err := s.issueRefreshToken(ctx, storage.RefreshToken{
				ClientID: "client", ConnectorID: "mock", Claims: storage.Claims{UserID: "user"},
			}, nil)
			rows, listErr := base.ListRefreshTokens(ctx)
			require.NoError(t, listErr)
			session, getErr := base.GetOfflineSessions(ctx, "user", "mock")
			require.NoError(t, getErr)
			if committed {
				require.NoError(t, err)
				require.NotEmpty(t, raw)
				require.Len(t, rows, 1)
				require.Equal(t, rows[0].ID, session.Refresh["client"].ID)
			} else {
				require.Error(t, err)
				require.Empty(t, raw)
				require.Empty(t, rows)
				require.Empty(t, session.Refresh)
			}
		})
	}
}

func TestAdmissionDoesNotPruneFreshCanonicalToken(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := memory.New(logger)
	s := &Server{
		storage: store, now: clock, logger: logger,
		refreshTokenPolicy: &RefreshTokenPolicy{now: clock, validIfNotUsedFor: time.Minute},
		refreshTokenLimits: map[string]uint32{"client": 1},
	}
	grant := storage.RefreshToken{ClientID: "client", ConnectorID: "mock", Claims: storage.Claims{UserID: "user"}}
	_, err := s.issueRefreshToken(ctx, grant, nil)
	require.NoError(t, err)
	session, err := store.GetOfflineSessions(ctx, "user", "mock")
	require.NoError(t, err)
	var id string
	for id = range session.Refresh["client"].Independent {
		break
	}

	// This is the state between UpdateRefreshToken and updateOfflineSession.
	require.NoError(t, store.UpdateRefreshToken(ctx, id, func(row storage.RefreshToken) (storage.RefreshToken, error) {
		row.LastUsed = now.Add(59 * time.Second)
		return row, nil
	}))
	now = now.Add(61 * time.Second)
	_, err = s.issueRefreshToken(ctx, grant, nil)
	require.ErrorIs(t, err, errRefreshTokenLimit)
	row, err := store.GetRefresh(ctx, id)
	require.NoError(t, err)
	require.Equal(t, now.Add(-2*time.Second), row.LastUsed)
}

type refreshDuringExpiryCheck struct {
	storage.Storage
	once     sync.Once
	lastUsed time.Time
}

func (s *refreshDuringExpiryCheck) UpdateRefreshToken(ctx context.Context, id string, update func(storage.RefreshToken) (storage.RefreshToken, error)) error {
	var interveningErr error
	s.once.Do(func() {
		interveningErr = s.Storage.UpdateRefreshToken(ctx, id, func(row storage.RefreshToken) (storage.RefreshToken, error) {
			row.LastUsed = s.lastUsed
			return row, nil
		})
	})
	if interveningErr != nil {
		return interveningErr
	}
	return s.Storage.UpdateRefreshToken(ctx, id, update)
}

func TestAdmissionRechecksExpiryAfterConcurrentRefresh(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	base := memory.New(logger)
	store := &refreshDuringExpiryCheck{Storage: base, lastUsed: now.Add(59 * time.Second)}
	s := &Server{
		storage: store, now: clock, logger: logger,
		refreshTokenPolicy: &RefreshTokenPolicy{now: clock, validIfNotUsedFor: time.Minute},
		refreshTokenLimits: map[string]uint32{"client": 1},
	}
	grant := storage.RefreshToken{ClientID: "client", ConnectorID: "mock", Claims: storage.Claims{UserID: "user"}}
	_, err := s.issueRefreshToken(ctx, grant, nil)
	require.NoError(t, err)
	session, err := base.GetOfflineSessions(ctx, "user", "mock")
	require.NoError(t, err)
	var id string
	for id = range session.Refresh["client"].Independent {
		break
	}

	now = now.Add(61 * time.Second)
	_, err = s.issueRefreshToken(ctx, grant, nil)
	require.ErrorIs(t, err, errRefreshTokenLimit)
	row, err := base.GetRefresh(ctx, id)
	require.NoError(t, err)
	require.Equal(t, store.lastUsed, row.LastUsed)
}

func TestRevokeRetryAfterIndexWriteFailure(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	base := memory.New(logger)
	row := storage.RefreshToken{
		ID: "grant", Token: "secret", ClientID: "client", ConnectorID: "mock",
		Claims: storage.Claims{UserID: "user"}, CreatedAt: time.Now(), LastUsed: time.Now(),
	}
	require.NoError(t, base.CreateRefresh(ctx, row))
	require.NoError(t, base.CreateOfflineSessions(ctx, storage.OfflineSessions{
		UserID: "user", ConnID: "mock", Refresh: map[string]*storage.RefreshTokenRef{
			"client": {ID: row.ID, ClientID: row.ClientID},
		},
	}))
	subject, err := internal.Marshal(&internal.IDTokenSubject{UserId: "user", ConnId: "mock"})
	require.NoError(t, err)
	req := &api.RevokeRefreshTokenReq{UserId: subject, ClientId: "client", RefreshTokenId: row.ID}
	failing := dexAPI{s: registrationFailure{Storage: base}, logger: logger}
	_, err = failing.RevokeRefreshToken(ctx, req)
	require.Error(t, err)
	_, err = base.GetRefresh(ctx, row.ID)
	require.ErrorIs(t, err, storage.ErrNotFound)
	session, err := base.GetOfflineSessions(ctx, "user", "mock")
	require.NoError(t, err)
	require.NotNil(t, session.Refresh["client"].Find(row.ID))

	retry := dexAPI{s: base, logger: logger}
	result, err := retry.RevokeRefreshToken(ctx, req)
	require.NoError(t, err)
	require.False(t, result.NotFound)
	session, err = base.GetOfflineSessions(ctx, "user", "mock")
	require.NoError(t, err)
	require.Empty(t, session.Refresh)
}

func TestRevokeUnindexedRowByGrantID(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := memory.New(logger)
	row := storage.RefreshToken{
		ID: "orphan", Token: "secret", ClientID: "client", ConnectorID: "mock",
		Claims: storage.Claims{UserID: "user"}, CreatedAt: time.Now(), LastUsed: time.Now(),
	}
	require.NoError(t, store.CreateRefresh(ctx, row))
	subject, err := internal.Marshal(&internal.IDTokenSubject{UserId: "user", ConnId: "mock"})
	require.NoError(t, err)
	admin := dexAPI{s: store, logger: logger}
	wrong, err := admin.RevokeRefreshToken(ctx, &api.RevokeRefreshTokenReq{
		UserId: subject, ClientId: "another-client", RefreshTokenId: row.ID,
	})
	require.NoError(t, err)
	require.True(t, wrong.NotFound)
	cleaned, err := admin.RevokeRefreshToken(ctx, &api.RevokeRefreshTokenReq{
		UserId: subject, ClientId: row.ClientID, RefreshTokenId: row.ID,
	})
	require.NoError(t, err)
	require.False(t, cleaned.NotFound)
	_, err = store.GetRefresh(ctx, row.ID)
	require.ErrorIs(t, err, storage.ErrNotFound)
}

func TestAdmissionRepairsMissingRefreshRow(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := memory.New(logger)
	s := &Server{
		storage: store, now: func() time.Time { return now }, logger: logger,
		refreshTokenPolicy: &RefreshTokenPolicy{now: func() time.Time { return now }},
		refreshTokenLimits: map[string]uint32{"client": 1},
	}
	grant := storage.RefreshToken{ClientID: "client", ConnectorID: "mock", Claims: storage.Claims{UserID: "user"}}
	_, err := s.issueRefreshToken(ctx, grant, nil)
	require.NoError(t, err)
	session, err := store.GetOfflineSessions(ctx, "user", "mock")
	require.NoError(t, err)
	var missingID string
	for missingID = range session.Refresh["client"].Independent {
		break
	}
	require.NoError(t, store.DeleteRefresh(ctx, missingID))
	_, err = s.issueRefreshToken(ctx, grant, nil)
	require.NoError(t, err)
	session, err = store.GetOfflineSessions(ctx, "user", "mock")
	require.NoError(t, err)
	require.Len(t, session.Refresh["client"].Independent, 1)
	require.Nil(t, session.Refresh["client"].Find(missingID))
}
