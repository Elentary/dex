//go:build cgo

package sqlretry

import (
	"errors"

	"github.com/mattn/go-sqlite3"
)

func sqliteConflict(err error) bool {
	var sq sqlite3.Error
	return errors.As(err, &sq) && (sq.Code == sqlite3.ErrBusy || sq.Code == sqlite3.ErrLocked)
}
