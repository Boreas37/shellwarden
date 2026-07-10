package db

import (
	"database/sql"
	"embed"
	"fmt"
	"sort"

	_ "github.com/lib/pq"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps the *sql.DB handle for the gateway.
type DB struct {
	*sql.DB
}

// Open connects to PostgreSQL using the given DSN and verifies the connection.
func Open(dsn string) (*DB, error) {
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return &DB{conn}, nil
}

// Migrate runs all embedded SQL migrations in lexical filename order. Each file
// is executed once per startup; statements use IF NOT EXISTS so re-running is
// safe (idempotent migrations for the MVP — no version tracking table yet).
// TODO: add a schema_migrations table to skip already-applied files.
func (d *DB) Migrate() error {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		content, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		if _, err := d.Exec(string(content)); err != nil {
			return fmt.Errorf("exec migration %s: %w", name, err)
		}
	}
	return nil
}
