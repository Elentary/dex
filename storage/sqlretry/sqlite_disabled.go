//go:build !cgo

package sqlretry

func sqliteConflict(error) bool { return false }
