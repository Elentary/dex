package apiserver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/dexidp/dex/api/v2"
	"github.com/dexidp/dex/server/tokens"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

func TestMultipleRefreshAPI(t *testing.T) {
	ctx := t.Context()
	logger := newLogger(t)
	s := memory.New(logger)
	client := newAPI(t, s, logger)
	defer client.Close()
	rt := tokens.NewRefreshStore(s, time.Now, logger)
	auth := tokens.Authorization{Client: storage.Client{ID: "client", RefreshTokenLimit: 3}, ConnectorID: "google", Claims: storage.Claims{UserID: "alice"}}
	for i := 0; i < 3; i++ {
		_, err := rt.Create(ctx, auth)
		require.NoError(t, err)
	}
	sub, err := tokens.GenSubject("alice", "google")
	require.NoError(t, err)
	list, err := client.ListRefresh(ctx, &api.ListRefreshReq{UserId: sub})
	require.NoError(t, err)
	require.Len(t, list.RefreshTokens, 3)
	id := list.RefreshTokens[0].Id
	// A token ID is not permission to revoke a different client's/user's grant.
	wrong, err := tokens.GenSubject("bob", "google")
	require.NoError(t, err)
	for _, req := range []*api.RevokeRefreshTokenReq{
		{UserId: wrong, ClientId: "client", RefreshTokenId: id},
		{UserId: sub, ClientId: "other", RefreshTokenId: id},
	} {
		resp, err := client.RevokeRefreshToken(ctx, req)
		require.NoError(t, err)
		require.True(t, resp.NotFound)
	}
	resp, err := client.RevokeRefreshToken(ctx, &api.RevokeRefreshTokenReq{UserId: sub, ClientId: "client", RefreshTokenId: id})
	require.NoError(t, err)
	require.False(t, resp.NotFound)
	list, err = client.ListRefresh(ctx, &api.ListRefreshReq{UserId: sub})
	require.NoError(t, err)
	require.Len(t, list.RefreshTokens, 2)
	all, err := client.RevokeRefresh(ctx, &api.RevokeRefreshReq{UserId: sub, ClientId: "client"})
	require.NoError(t, err)
	require.False(t, all.NotFound)
	list, err = client.ListRefresh(ctx, &api.ListRefreshReq{UserId: sub})
	require.NoError(t, err)
	require.Empty(t, list.RefreshTokens)
}

func TestRefreshLimitAPICompatibility(t *testing.T) {
	ctx := t.Context()
	logger := newLogger(t)
	s := memory.New(logger)
	client := newAPI(t, s, logger)
	defer client.Close()
	_, err := client.CreateClient(ctx, &api.CreateClientReq{Client: &api.Client{Id: "client", RefreshTokenLimit: 50}})
	require.NoError(t, err)
	// An older client omits the new field: changing the name preserves the quota.
	_, err = client.UpdateClient(ctx, &api.UpdateClientReq{Id: "client", Name: "renamed"})
	require.NoError(t, err)
	got, err := client.GetClient(ctx, &api.GetClientReq{Id: "client"})
	require.NoError(t, err)
	require.EqualValues(t, 50, got.Client.RefreshTokenLimit)
	list, err := client.ListClients(ctx, &api.ListClientReq{})
	require.NoError(t, err)
	require.EqualValues(t, 50, list.Clients[0].RefreshTokenLimit)
	_, err = client.UpdateClient(ctx, &api.UpdateClientReq{Id: "client", RefreshTokenLifetime: proto.String("session")})
	require.Error(t, err)
	_, err = client.CreateClient(ctx, &api.CreateClientReq{Client: &api.Client{Id: "bound", RefreshTokenLimit: 1, RefreshTokenLifetime: "session"}})
	require.Error(t, err)
	// Explicit zero and changing the lifetime in the same request is valid.
	_, err = client.UpdateClient(ctx, &api.UpdateClientReq{Id: "client", RefreshTokenLimit: proto.Uint32(0), RefreshTokenLifetime: proto.String("session")})
	require.NoError(t, err)
	got, err = client.GetClient(ctx, &api.GetClientReq{Id: "client"})
	require.NoError(t, err)
	require.Zero(t, got.Client.RefreshTokenLimit)
}
