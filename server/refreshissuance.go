package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
)

const refreshTokenLimitDescription = "Refresh token limit reached. Revoke an existing refresh token before signing in again."

var (
	errRefreshTokenLimit  = errors.New("refresh token limit reached")
	errRefreshStillActive = errors.New("refresh token is still active")
)

type expiredRefreshRef struct {
	id      string
	pending bool
}

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
	return s.issueRefreshTokenForDevice(ctx, refresh, offlineConnectorData, nil)
}

func (s *Server) issueRefreshTokenForDevice(ctx context.Context, refresh storage.RefreshToken, offlineConnectorData []byte, device *storage.DeviceToken) (string, error) {
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
	if device != nil && limit > 0 {
		ref.DeviceCode = device.DeviceCode
		ref.PendingUntil = device.Expiry
	}
	var expiredIDs []expiredRefreshRef
	if limit > 0 {
		expiredIDs, err = s.expiredRefreshTokenIDs(ctx, userID, connID, refresh.ClientID)
		if err != nil {
			deleteRefreshRows(ctx, s.storage, s.logger, []string{ref.ID})
			return "", fmt.Errorf("check existing refresh tokens: %w", err)
		}
	}
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
			for _, candidate := range expiredIDs {
				current := old.Refresh[ref.ClientID].Find(candidate.id)
				if candidate.pending && (current == nil || current.PendingUntil.IsZero() || !s.now().After(current.PendingUntil)) {
					continue
				}
				if removeRefreshRef(&old, ref.ClientID, candidate.id) {
					removed = append(removed, candidate.id)
				}
			}
			client = old.Refresh[ref.ClientID]
			if client == nil {
				client = &storage.RefreshTokenRef{ClientID: ref.ClientID}
			}
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
			deleteRefreshRows(ctx, s.storage, s.logger, []string{ref.ID})
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
		// A write can commit even if its acknowledgement is lost. Read the
		// index before cleaning up a token that was never delivered.
		checkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		session, readErr := s.storage.GetOfflineSessions(checkCtx, userID, connID)
		if errors.Is(readErr, storage.ErrNotFound) ||
			readErr == nil && (session.UserID != userID || session.ConnID != connID || session.Refresh[ref.ClientID].Find(ref.ID) == nil) {
			deleteRefreshRows(checkCtx, s.storage, s.logger, []string{ref.ID})
			return "", fmt.Errorf("register refresh token: %w", err)
		}
		if readErr != nil {
			return "", fmt.Errorf("register refresh token: %w", err)
		}
	}
	deleteRefreshRows(ctx, s.storage, s.logger, removed)
	return raw, nil
}

func removeRefreshRef(session *storage.OfflineSessions, clientID, id string) bool {
	client := session.Refresh[clientID]
	if client.Find(id) == nil {
		return false
	}
	if client.ID == id {
		*client = storage.RefreshTokenRef{ClientID: clientID, Independent: client.Independent}
	} else {
		delete(client.Independent, id)
	}
	if client.ID == "" && len(client.Independent) == 0 {
		delete(session.Refresh, clientID)
	}
	return true
}

func (s *Server) refreshRowExpired(row storage.RefreshToken) bool {
	return s.refreshTokenPolicy.CompletelyExpired(row.CreatedAt) ||
		s.refreshTokenPolicy.ExpiredBecauseUnused(row.LastUsed)
}

// expiredRefreshTokenIDs checks the canonical rows outside the offline-session
// updater. Rotating the secret atomically prevents an in-flight refresh from
// reviving a row after its reference is removed.
func (s *Server) expiredRefreshTokenIDs(ctx context.Context, userID, connID, clientID string) ([]expiredRefreshRef, error) {
	session, err := s.storage.GetOfflineSessions(ctx, userID, connID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if session.UserID != userID || session.ConnID != connID {
		return nil, errors.New("offline session belongs to another identity")
	}
	client := session.Refresh[clientID]
	if client == nil {
		return nil, nil
	}
	var refs []*storage.RefreshTokenRef
	if client.ID != "" {
		refs = append(refs, client)
	}
	for _, ref := range client.Independent {
		if ref != nil {
			refs = append(refs, ref)
		}
	}
	var expired []expiredRefreshRef
	for _, ref := range refs {
		id := ref.ID
		if !ref.PendingUntil.IsZero() {
			if s.now().After(ref.PendingUntil) {
				expired = append(expired, expiredRefreshRef{id: id, pending: true})
			}
			continue
		}
		row, err := s.storage.GetRefresh(ctx, id)
		if errors.Is(err, storage.ErrNotFound) {
			expired = append(expired, expiredRefreshRef{id: id})
			continue
		}
		if err != nil {
			return nil, err
		}
		if row.ID != id || row.ClientID != clientID || row.ConnectorID != connID || row.Claims.UserID != userID {
			return nil, fmt.Errorf("refresh token %q belongs to another identity", id)
		}
		if !s.refreshRowExpired(row) {
			continue
		}
		retiredSecret := storage.NewID()
		err = s.storage.UpdateRefreshToken(ctx, id, func(old storage.RefreshToken) (storage.RefreshToken, error) {
			if old.ID != id {
				return old, storage.ErrNotFound
			}
			if old.ClientID != clientID || old.ConnectorID != connID || old.Claims.UserID != userID {
				return old, fmt.Errorf("refresh token %q changed owner", id)
			}
			if !s.refreshRowExpired(old) {
				return old, errRefreshStillActive
			}
			old.Token = retiredSecret
			old.ObsoleteToken = ""
			return old, nil
		})
		switch {
		case errors.Is(err, errRefreshStillActive):
			continue
		case err == nil, errors.Is(err, storage.ErrNotFound):
			expired = append(expired, expiredRefreshRef{id: id})
		default:
			return nil, err
		}
	}
	return expired, nil
}

func deleteRefreshRows(ctx context.Context, store storage.Storage, logger *slog.Logger, ids []string) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	for _, id := range ids {
		if err := store.DeleteRefresh(cleanupCtx, id); err != nil && !errors.Is(err, storage.ErrNotFound) {
			logger.ErrorContext(cleanupCtx, "failed to delete unindexed refresh token", "token_id", id, "err", err)
		}
	}
}
