package agent

import (
	"database/sql"
	"fmt"

	"github.com/1AbdulkarimMousa/SchemaSculptor/util"
	_ "github.com/lib/pq"
)

// SchemaRegistry holds the database schema information
type SchemaRegistry struct {
	Tables []Table
	db     *sql.DB
}

// NewSchemaRegistry creates a new schema registry and connects to the database
func NewSchemaRegistry() (*SchemaRegistry, error) {
	// Connect to the database using environment variables
	connStr := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=%s",
		util.DBHost, util.DBPort, util.DBName, util.DBUser, util.DBPass, util.DBSSl,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &SchemaRegistry{
		db: db,
	}, nil
}

// Close closes the database connection
func (sr *SchemaRegistry) Close() error {
	if sr.db != nil {
		return sr.db.Close()
	}
	return nil
}
