package storage

import "fmt"

// IsActive accepts both legacy and independently issued grants. Registration
// and revocation states must never be accepted by lookup or rotation.
func (r RefreshToken) IsActive() bool {
	return r.State == "" || r.State == RefreshTokenActive
}

// ValidateRefreshTokenPolicy validates the complete client policy, including
// partial API updates applied to the existing client.
func (c Client) ValidateRefreshTokenPolicy() error {
	if err := ValidateRefreshTokenLifetime(c.RefreshTokenLifetime); err != nil {
		return err
	}
	if c.RefreshTokenLimit > 0 && c.RefreshBoundToSession() {
		return fmt.Errorf("refreshTokenLimit requires standalone refreshTokenLifetime")
	}
	return nil
}

// RefreshTokenRefs returns references from both indexes. Callers must not mutate
// the returned references outside an UpdateOfflineSessions callback.
func (s OfflineSessions) RefreshTokenRefs() []*RefreshTokenRef {
	refs := make([]*RefreshTokenRef, 0, len(s.Refresh)+len(s.RefreshTokens))
	for _, ref := range s.Refresh {
		if ref != nil {
			refs = append(refs, ref)
		}
	}
	for _, ref := range s.RefreshTokens {
		if ref != nil {
			refs = append(refs, ref)
		}
	}
	return refs
}

// RefreshTokenRef finds a grant with the exact client and token ID.
func (s OfflineSessions) RefreshTokenRef(clientID, id string) *RefreshTokenRef {
	if ref := s.Refresh[clientID]; ref != nil && ref.ID == id {
		return ref
	}
	if ref := s.RefreshTokens[id]; ref != nil && ref.ClientID == clientID && ref.ID == id {
		return ref
	}
	return nil
}

// DeleteRefreshTokenRef removes the exact grant, preserving concurrent logins.
func (s OfflineSessions) DeleteRefreshTokenRef(clientID, id string) {
	if ref := s.Refresh[clientID]; ref != nil && ref.ID == id {
		delete(s.Refresh, clientID)
	}
	if ref := s.RefreshTokens[id]; ref != nil && ref.ClientID == clientID {
		delete(s.RefreshTokens, id)
	}
}

// Clone copies the mutable indexes for storage backends that keep Go objects.
func (s OfflineSessions) Clone() OfflineSessions {
	clone := func(refs map[string]*RefreshTokenRef) map[string]*RefreshTokenRef {
		if refs == nil {
			return nil
		}
		out := make(map[string]*RefreshTokenRef, len(refs))
		for k, ref := range refs {
			if ref != nil {
				r := *ref
				out[k] = &r
			} else {
				out[k] = nil
			}
		}
		return out
	}
	s.Refresh = clone(s.Refresh)
	s.RefreshTokens = clone(s.RefreshTokens)
	s.ConnectorData = append([]byte(nil), s.ConnectorData...)
	return s
}
