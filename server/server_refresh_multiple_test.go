package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/server/tokens"
	"github.com/dexidp/dex/storage"
)

func TestIndependentRefreshGrantHTTP(t *testing.T) {
	for _, grant := range []string{"authorization_code", "password", "device"} {
		t.Run(grant, func(t *testing.T) {
			ctx := t.Context()
			httpServer, s := newTestServer(t, func(c *Config) {
				c.PasswordConnector = "test"
				c.Now = time.Now
				c.RefreshTokenPolicy = tokens.NewRefreshStrategy(true, 0, 0, 0, nil)
			})
			defer httpServer.Close()
			mockConnectorDataTestStorage(t, s.storage)
			require.NoError(t, s.storage.UpdateClient(ctx, "test", func(old storage.Client) (storage.Client, error) { old.RefreshTokenLimit = 2; return old, nil }))
			post := func(form url.Values) *httptest.ResponseRecorder {
				req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth("test", "barfoo")
				rr := httptest.NewRecorder()
				s.ServeHTTP(rr, req)
				return rr
			}
			login := func(offline bool) *httptest.ResponseRecorder {
				scopes := []string{"openid", "email", "profile", "groups"}
				if offline {
					scopes = append(scopes, "offline_access")
				}
				if grant == "password" {
					return post(url.Values{"grant_type": {"password"}, "username": {"test"}, "password": {"test"}, "scope": {strings.Join(scopes, " ")}})
				}
				code := storage.AuthCode{ID: storage.NewID(), ClientID: "test", ConnectorID: "test", RedirectURI: "https://auth.example.com", Scopes: scopes, Claims: storage.Claims{UserID: "alice", Username: "alice", Email: "alice@example.com", EmailVerified: true, Groups: []string{"team"}}, Expiry: time.Now().Add(time.Minute), SessionID: "same-browser"}
				if grant == "device" {
					code.RedirectURI = s.issuerURL.AbsPath(oauth2.DeviceCallbackURI)
				}
				require.NoError(t, s.storage.CreateAuthCode(ctx, code))
				if grant == "authorization_code" {
					return post(url.Values{"grant_type": {"authorization_code"}, "code": {code.ID}, "redirect_uri": {code.RedirectURI}})
				}
				userCode, deviceCode := storage.NewID(), storage.NewID()
				require.NoError(t, s.storage.CreateDeviceRequest(ctx, storage.DeviceRequest{UserCode: userCode, DeviceCode: deviceCode, ClientID: "test", ClientSecret: "barfoo", Expiry: time.Now().Add(time.Minute)}))
				require.NoError(t, s.storage.CreateDeviceToken(ctx, storage.DeviceToken{DeviceCode: deviceCode, Status: oauth2.DeviceTokenPending, Expiry: time.Now().Add(time.Minute)}))
				req := httptest.NewRequest("GET", oauth2.DeviceCallbackURI+"?"+url.Values{"state": {userCode}, "code": {code.ID}}.Encode(), nil)
				rr := httptest.NewRecorder()
				s.ServeHTTP(rr, req)
				require.Contains(t, []int{http.StatusOK, http.StatusBadRequest}, rr.Code, rr.Body.String())
				return post(url.Values{"grant_type": {oauth2.GrantTypeDeviceCode}, "device_code": {deviceCode}})
			}
			var responses []map[string]any
			for i := 0; i < 2; i++ {
				rr := login(true)
				require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
				var resp map[string]any
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
				require.NotEmpty(t, resp["refresh_token"])
				responses = append(responses, resp)
			}
			a, b := idTokenClaims(t, responses[0]["id_token"].(string)), idTokenClaims(t, responses[1]["id_token"].(string))
			for _, claim := range []string{"sub", "email", "groups"} {
				require.Equal(t, a[claim], b[claim])
			}
			rejected := login(true)
			require.Equal(t, http.StatusBadRequest, rejected.Code, rejected.Body.String())
			var body map[string]any
			require.NoError(t, json.Unmarshal(rejected.Body.Bytes(), &body))
			require.Equal(t, "invalid_grant", body["error"])
			require.Contains(t, body["error_description"], "refresh token limit")
			require.NotContains(t, body, "id_token")
			require.NotContains(t, body, "access_token")
			require.NotContains(t, body, "refresh_token")
			// Capacity never blocks requests that do not ask for a refresh token.
			require.Equal(t, http.StatusOK, login(false).Code)
			// Each device can rotate repeatedly even after the other's login/rotation.
			for i := 0; i < 3; i++ {
				for j, resp := range responses {
					rr := post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {resp["refresh_token"].(string)}})
					require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
					require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &responses[j]))
					claims := idTokenClaims(t, responses[j]["id_token"].(string))
					require.Equal(t, a["sub"], claims["sub"])
				}
			}
		})
	}
}

func TestIndependentRefreshSurvivesBrowserLogout(t *testing.T) {
	ctx := t.Context()
	httpServer, s := newTestServerWithSessions(t, nil)
	defer httpServer.Close()
	client := storage.Client{ID: "cli", Secret: "secret", RefreshTokenLimit: 2}
	require.NoError(t, s.storage.CreateClient(ctx, client))
	require.NoError(t, s.storage.CreateAuthSession(ctx, storage.AuthSession{ID: "browser", Secret: testSessionSecret("browser"), UserID: "alice", ConnectorID: "mock", CreatedAt: time.Now(), LastActivity: time.Now(), ClientStates: map[string]*storage.ClientAuthState{"cli": {AuthenticatedAt: time.Now()}}}))
	auth := tokens.Authorization{Client: client, ConnectorID: "mock", Claims: storage.Claims{UserID: "alice"}, SessionID: "browser"}
	var raw []string
	for i := 0; i < 2; i++ {
		token, err := s.issuer.Refresh.Create(ctx, auth)
		require.NoError(t, err)
		raw = append(raw, token)
	}
	hint := newTestIDToken(t, s, "cli", "alice", "mock", "browser")
	req := httptest.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(hint), nil)
	req.AddCookie(testSessionCookie("browser"))
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	_, err := s.storage.GetAuthSession(ctx, "browser")
	require.ErrorIs(t, err, storage.ErrNotFound)
	for _, token := range raw {
		req := httptest.NewRequest("POST", "/token/introspect", strings.NewReader(url.Values{"token": {token}, "token_type_hint": {"refresh_token"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var body map[string]any
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		require.Equal(t, true, body["active"])
	}
}
