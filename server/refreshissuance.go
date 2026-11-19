package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
)

const refreshTokenLimitDescription = "Refresh token limit reached. Revoke an existing refresh token before signing in again."

var errRefreshTokenLimit = errors.New("refresh token limit reached")

func (s *Server) writeTokenIssueError(ctx context.Context, w http.ResponseWriter, err error) {
	if errors.Is(err, errRefreshTokenLimit) {
		s.tokenErrHelper(w, errInvalidGrant, refreshTokenLimitDescription, http.StatusBadRequest)
		return
	}
	s.logger.ErrorContext(ctx, "failed to issue tokens", "err", err)
	s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
}

// issueRefreshToken stores the token first and registers its ID before handing
// out the secret. Only tokens with a matching offline-session reference work.
func (s *Server) issueRefreshToken(ctx context.Context, refresh storage.RefreshToken, offlineConnectorData []byte) (string, error) {
	refresh.ID = storage.NewID()
	refresh.Token = storage.NewID()
	refresh.CreatedAt = s.now()
	refresh.LastUsed = refresh.CreatedAt
	raw, err := internal.Marshal(&internal.RefreshToken{RefreshId: refresh.ID, Token: refresh.Token})
	if err != nil {
		return "", fmt.Errorf("encode refresh token: %w", err)
	}
	if err := s.storage.CreateRefresh(ctx, refresh); err != nil {
		return "", fmt.Errorf("create refresh token: %w", err)
	}

	userID, connID := refresh.Claims.UserID, refresh.ConnectorID
	ref := storage.RefreshTokenRef{
		ID:        refresh.ID,
		ClientID:  refresh.ClientID,
		CreatedAt: refresh.CreatedAt,
		LastUsed:  refresh.LastUsed,
	}
	limit := s.refreshTokenLimits[refresh.ClientID]
	var removed []string
	register := func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
		// Retrying storage backends can run this callback more than once.
		removed = nil
		if old.UserID != userID || old.ConnID != connID {
			return old, errors.New("offline session belongs to another identity")
		}
		if old.Refresh == nil {
			old.Refresh = make(map[string]*storage.RefreshTokenRef)
		}
		client := old.Refresh[ref.ClientID]
		if client == nil {
			client = &storage.RefreshTokenRef{ClientID: ref.ClientID}
		}
		if limit == 0 {
			if client.ID != "" {
				removed = append(removed, client.ID)
			}
			legacy := ref
			legacy.Independent = client.Independent
			client = &legacy
		} else {
			removed = s.pruneExpiredRefreshRefs(client)
			count := len(client.Independent)
			if client.ID != "" {
				count++
			}
			if uint64(count) >= uint64(limit) {
				return old, errRefreshTokenLimit
			}
			if client.Independent == nil {
				client.Independent = make(map[string]*storage.RefreshTokenRef)
			}
			client.Independent[ref.ID] = &ref
		}
		old.Refresh[ref.ClientID] = client
		if offlineConnectorData != nil {
			old.ConnectorData = offlineConnectorData
		}
		return old, nil
	}
	err = s.storage.UpdateOfflineSessions(ctx, userID, connID, register)
	if errors.Is(err, storage.ErrNotFound) {
		session, registerErr := register(storage.OfflineSessions{UserID: userID, ConnID: connID})
		if registerErr != nil {
			return "", registerErr
		}
		err = s.storage.CreateOfflineSessions(ctx, session)
		if errors.Is(err, storage.ErrAlreadyExists) {
			err = s.storage.UpdateOfflineSessions(ctx, userID, connID, register)
		}
	}
	if errors.Is(err, errRefreshTokenLimit) {
		deleteRefreshRows(ctx, s.storage, s.logger, []string{ref.ID})
		return "", errRefreshTokenLimit
	}
	if err != nil {
		// A write can commit even if its acknowledgement is lost. Confirm
		// membership before returning the token. Keep the new row if the
		// registration outcome is unknown.
		session, readErr := s.storage.GetOfflineSessions(ctx, userID, connID)
		if readErr != nil || session.UserID != userID || session.ConnID != connID || session.Refresh[ref.ClientID].Find(ref.ID) == nil {
			return "", fmt.Errorf("register refresh token: %w", err)
		}
	}
	deleteRefreshRows(ctx, s.storage, s.logger, removed)
	return raw, nil
}

// Expiration uses the last successful use recorded on the reference. Pruning
// and extending that lifetime are serialized by the same offline-session update.
func (s *Server) refreshRefExpired(ref *storage.RefreshTokenRef) bool {
	return !ref.CreatedAt.IsZero() && s.refreshTokenPolicy.CompletelyExpired(ref.CreatedAt) ||
		!ref.LastUsed.IsZero() && s.refreshTokenPolicy.ExpiredBecauseUnused(ref.LastUsed)
}

func (s *Server) pruneExpiredRefreshRefs(client *storage.RefreshTokenRef) []string {
	var removed []string
	if client.ID != "" && s.refreshRefExpired(client) {
		removed = append(removed, client.ID)
		*client = storage.RefreshTokenRef{ClientID: client.ClientID, Independent: client.Independent}
	}
	for id, ref := range client.Independent {
		if ref == nil || s.refreshRefExpired(ref) {
			delete(client.Independent, id)
			removed = append(removed, id)
		}
	}
	return removed
}

func deleteRefreshRows(ctx context.Context, store storage.Storage, logger *slog.Logger, ids []string) {
	for _, id := range ids {
		if err := store.DeleteRefresh(ctx, id); err != nil && !errors.Is(err, storage.ErrNotFound) {
			logger.ErrorContext(ctx, "failed to delete unindexed refresh token", "token_id", id, "err", err)
		}
	}
}
