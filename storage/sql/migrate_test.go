//go:build cgo
// +build cgo

package sql

import (
	"database/sql"
	"log/slog"
	"testing"

	sqlite3 "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
)

func TestMigrate(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	logger := slog.New(slog.DiscardHandler)

	errCheck := func(err error) bool {
		sqlErr, ok := err.(sqlite3.Error)
		if !ok {
			return false
		}
		return sqlErr.ExtendedCode == sqlite3.ErrConstraintUnique
	}

	var sqliteMigrations []migration
	for _, m := range migrations {
		if m.flavor == nil || m.flavor == &flavorSQLite3 {
			sqliteMigrations = append(sqliteMigrations, m)
		}
	}

	c := &conn{db, &flavorSQLite3, logger, errCheck}
	for _, want := range []int{len(sqliteMigrations), 0} {
		got, err := c.migrate()
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("expected %d migrations, got %d", want, got)
		}
	}
}

func TestRefreshGrantMigrationFromLegacySchema(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)
	c := &conn{db: db, flavor: &flavorSQLite3, logger: slog.New(slog.DiscardHandler)}
	// Build the release schema without the new additive migration.
	count := 0
	for _, m := range migrations[:len(migrations)-1] {
		if m.flavor != nil && m.flavor != &flavorSQLite3 {
			continue
		}
		for _, stmt := range m.stmts {
			_, err := c.Exec(stmt)
			require.NoError(t, err)
		}
		count++
	}
	_, err = c.Exec(`create table migrations (num integer not null, at timestamp not null)`)
	require.NoError(t, err)
	_, err = c.Exec(`insert into migrations (num, at) values ($1, now())`, count)
	require.NoError(t, err)
	_, err = c.Exec(`insert into client (id, secret, redirect_uris, trusted_peers, public, name, logo_url) values ('legacy', 'secret', $1, $2, false, 'legacy', '')`, []byte(`[]`), []byte(`[]`))
	require.NoError(t, err)
	_, err = c.Exec(`insert into offline_session (user_id, conn_id, refresh) values ('alice', 'google', $1)`, []byte(`{"legacy":{"ID":"existing","ClientID":"legacy"}}`))
	require.NoError(t, err)
	_, err = c.Exec(`insert into refresh_token (id, client_id, scopes, nonce, claims_user_id, claims_username, claims_email, claims_email_verified, claims_groups, connector_id, token) values ('existing','legacy',$1,'nonce','alice','alice','alice@example.com',true,$2,'google','unchanged')`, []byte(`[]`), []byte(`[]`))
	require.NoError(t, err)
	n, err := c.migrate()
	require.NoError(t, err)
	require.Equal(t, 1, n)
	client, err := c.GetClient(t.Context(), "legacy")
	require.NoError(t, err)
	require.Zero(t, client.RefreshTokenLimit)
	session, err := c.GetOfflineSessions(t.Context(), "alice", "google")
	require.NoError(t, err)
	require.Empty(t, session.RefreshTokens)
	require.Equal(t, "existing", session.Refresh["legacy"].ID)
	row, err := c.GetRefresh(t.Context(), "existing")
	require.NoError(t, err)
	require.Empty(t, row.State)
	require.Equal(t, "unchanged", row.Token)
}
