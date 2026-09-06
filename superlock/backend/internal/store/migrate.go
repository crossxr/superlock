package store

import (
	"fmt"
	"log"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// Migrate runs all pending migrations from the given directory.
func Migrate(databaseURL, migrationsDir string) error {
	m, err := migrate.New(
		fmt.Sprintf("file://%s", migrationsDir),
		databaseURL,
	)
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}
	defer m.Close()

	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		if strings.Contains(strings.ToLower(err.Error()), "dirty") {
			version, _, _ := m.Version()
			prevVersion := int(version) - 1
			if prevVersion < 0 {
				prevVersion = 0
			}
			log.Printf("Migration is dirty at version %d. Forcing version %d and retrying...", version, prevVersion)
			if ferr := m.Force(prevVersion); ferr != nil {
				return fmt.Errorf("force version %d: %w", prevVersion, ferr)
			}
			// Retry migration after forcing previous version
			err = m.Up()
		}
	}

	if err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migrate up: %w", err)
	}

	log.Println("Migrations applied successfully")
	return nil
}
