package etcd

import (
	"context"
	"encoding/json"
	"fmt"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/dexidp/dex/storage"
)

func (c *conn) ListRefreshTokensPage(ctx context.Context, cursor string, limit int) ([]storage.RefreshToken, string, error) {
	if limit < 1 {
		return nil, "", fmt.Errorf("refresh page limit must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, defaultStorageTimeout)
	defer cancel()
	start := refreshTokenPrefix
	if cursor != "" {
		start = cursor + "\x00"
	}
	res, err := c.db.Get(ctx, start, clientv3.WithRange(clientv3.GetPrefixRangeEnd(refreshTokenPrefix)), clientv3.WithSort(clientv3.SortByKey, clientv3.SortAscend), clientv3.WithLimit(int64(limit)))
	if err != nil {
		return nil, "", err
	}
	tokens := make([]storage.RefreshToken, 0, len(res.Kvs))
	for _, kv := range res.Kvs {
		var token RefreshToken
		if err := json.Unmarshal(kv.Value, &token); err != nil {
			return nil, "", err
		}
		tokens = append(tokens, toStorageRefreshToken(token))
	}
	next := ""
	if res.More && len(res.Kvs) > 0 {
		next = string(res.Kvs[len(res.Kvs)-1].Key)
	}
	return tokens, next, nil
}
