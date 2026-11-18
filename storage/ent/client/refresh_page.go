package client

import (
	"context"
	"fmt"

	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/ent/db/refreshtoken"
)

func (d *Database) ListRefreshTokensPage(ctx context.Context, cursor string, limit int) ([]storage.RefreshToken, string, error) {
	if limit < 1 {
		return nil, "", fmt.Errorf("refresh page limit must be positive")
	}
	rows, err := d.client.RefreshToken.Query().Where(refreshtoken.IDGT(cursor)).Order(refreshtoken.ByID()).Limit(limit).All(ctx)
	if err != nil {
		return nil, "", err
	}
	tokens := make([]storage.RefreshToken, 0, len(rows))
	for _, row := range rows {
		tokens = append(tokens, toStorageRefreshToken(row))
	}
	next := ""
	if len(tokens) == limit {
		next = tokens[len(tokens)-1].ID
	}
	return tokens, next, nil
}
