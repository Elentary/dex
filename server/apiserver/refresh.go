package apiserver

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dexidp/dex/api/v2"
	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
)

func (d dexAPI) ListRefresh(ctx context.Context, req *api.ListRefreshReq) (*api.ListRefreshResp, error) {
	id := new(internal.IDTokenSubject)
	if err := internal.Unmarshal(req.UserId, id); err != nil {
		d.logger.Error("failed to unmarshal ID Token subject", "err", err)
		return nil, err
	}

	offlineSessions, err := d.s.GetOfflineSessions(ctx, id.UserId, id.ConnId)
	if err != nil {
		if err == storage.ErrNotFound {
			// This means that this user-client pair does not have a refresh token yet.
			// An empty list should be returned instead of an error.
			return &api.ListRefreshResp{}, nil
		}
		d.logger.Error("failed to list refresh tokens here", "err", err)
		return nil, err
	}

	refreshTokenRefs := make([]*api.RefreshTokenRef, 0, len(offlineSessions.RefreshTokenRefs()))
	for _, session := range offlineSessions.RefreshTokenRefs() {
		r := api.RefreshTokenRef{
			Id:        session.ID,
			ClientId:  session.ClientID,
			CreatedAt: session.CreatedAt.Unix(),
			LastUsed:  session.LastUsed.Unix(),
		}
		refreshTokenRefs = append(refreshTokenRefs, &r)
	}

	return &api.ListRefreshResp{
		RefreshTokens: refreshTokenRefs,
	}, nil
}

func (d dexAPI) RevokeRefresh(ctx context.Context, req *api.RevokeRefreshReq) (*api.RevokeRefreshResp, error) {
	id := new(internal.IDTokenSubject)
	if err := internal.Unmarshal(req.UserId, id); err != nil {
		d.logger.Error("failed to unmarshal ID Token subject", "err", err)
		return nil, err
	}

	n, err := d.refresh.Revoke(ctx, id.UserId, id.ConnId, func(ref *storage.RefreshTokenRef) bool { return ref.ClientID == req.ClientId })
	if err != nil {
		return nil, err
	}
	return &api.RevokeRefreshResp{NotFound: n == 0}, nil
}

func (d dexAPI) RevokeRefreshToken(ctx context.Context, req *api.RevokeRefreshTokenReq) (*api.RevokeRefreshTokenResp, error) {
	id := new(internal.IDTokenSubject)
	if req.UserId == "" || req.ClientId == "" || req.RefreshTokenId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id, client_id and refresh_token_id are required")
	}
	if err := internal.Unmarshal(req.UserId, id); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id")
	}
	n, err := d.refresh.Revoke(ctx, id.UserId, id.ConnId, func(ref *storage.RefreshTokenRef) bool {
		return ref.ClientID == req.ClientId && ref.ID == req.RefreshTokenId
	})
	if err != nil {
		return nil, err
	}
	return &api.RevokeRefreshTokenResp{NotFound: n == 0}, nil
}

// revokeUserRefreshTokens revokes all refresh tokens for a user/connector pair
// and cleans up offline session references. Errors are logged but not returned
// (best-effort).
//
// This is deliberately broader than what RP-initiated logout does. That flow revokes
// only the client that asked for it, because it has a requesting client to scope to
// and no mandate to touch anyone else's credentials (see revokeRequestingClient in
// server/logout). An administrative call has neither: there is no client_id in the
// request, and ending access is the entire point of the operation. Callers that want
// one client's token gone use RevokeRefresh.
func (d dexAPI) revokeUserRefreshTokens(ctx context.Context, userID, connectorID string) {
	d.refresh.RevokeAll(ctx, userID, connectorID)
}
