package memory

import (
	"context"
	"fmt"
	"sort"

	"github.com/dexidp/dex/storage"
)

func (s *memStorage) ListRefreshTokensPage(ctx context.Context, cursor string, limit int) (tokens []storage.RefreshToken, next string, err error) {
	if limit < 1 {
		return nil, "", fmt.Errorf("refresh page limit must be positive")
	}
	s.tx(func() {
		ids := make([]string, 0, len(s.refreshTokens))
		for id := range s.refreshTokens {
			if id > cursor {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		if len(ids) > limit {
			ids = ids[:limit]
			next = ids[len(ids)-1]
		}
		for _, id := range ids {
			tokens = append(tokens, s.refreshTokens[id])
		}
	})
	return
}
