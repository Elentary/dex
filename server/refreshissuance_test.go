package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

	admin := newAPI(keepRefreshRows{s.storage}, s.logger, t)
	defer admin.Close()
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
	revoked, err := admin.RevokeRefreshToken(ctx, &api.RevokeRefreshTokenReq{
		UserId: legacyID.Subject, ClientId: client.ID, RefreshTokenId: token.RefreshId,
	})
	require.NoError(t, err)
	require.False(t, revoked.NotFound)
	_, err = s.storage.GetRefresh(ctx, token.RefreshId)
	require.NoError(t, err, "revocation must work even if the token row remains")
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
