package kubernetes

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"github.com/dexidp/dex/storage"
)

func (cli *client) ListRefreshTokensPage(ctx context.Context, cursor string, limit int) ([]storage.RefreshToken, string, error) {
	if limit < 1 {
		return nil, "", fmt.Errorf("refresh page limit must be positive")
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	params := url.Values{"limit": {strconv.Itoa(limit)}}
	if cursor != "" {
		params.Set("continue", cursor)
	}
	u, err := cli.urlForWithParams(cli.apiVersion, cli.namespace, resourceRefreshToken, "", params)
	if err != nil {
		return nil, "", err
	}
	var page RefreshList
	if err := cli.getURL(u, &page); err != nil {
		return nil, "", err
	}
	tokens := make([]storage.RefreshToken, 0, len(page.RefreshTokens))
	for _, row := range page.RefreshTokens {
		tokens = append(tokens, toStorageRefreshToken(row))
	}
	return tokens, page.Continue, nil
}
