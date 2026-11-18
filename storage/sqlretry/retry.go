// Package sqlretry retries serialization conflicts for pure storage updaters.
package sqlretry

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/lib/pq"
)

// Do reruns a complete, rolled-back transaction on a known concurrency error.
// Other errors (including ambiguous network/commit failures) are not retried.
func Do(ctx context.Context, fn func() error) error {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := fn()
		if err == nil || attempt == 31 || !conflict(err) {
			return err
		}
		delay := min(250, 5<<min(attempt, 6))
		timer := time.NewTimer(time.Duration(delay/2+rand.IntN(delay/2+1)) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func conflict(err error) bool {
	var pg *pq.Error
	if errors.As(err, &pg) {
		return pg.Code == "40001" || pg.Code == "40P01"
	}
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		return my.Number == 1213 || my.Number == 1205
	}
	return sqliteConflict(err)
}
