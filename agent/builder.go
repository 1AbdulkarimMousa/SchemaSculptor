package agent

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

func BuildQueries() {
	// Initialize the schema registry
	sr, err := NewSchemaRegistry()
	if err != nil {
		log.Fatalf("Failed to create schema registry: %v", err)
	}
	defer sr.Close()

	// Load the schema
	if err := sr.LoadSchema(context.Background()); err != nil {
		log.Fatalf("Failed to load schema: %v", err)
	}

	// Get the current working directory
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current working directory: %v", err)
	}

	projectRoot := filepath.Dir(cwd)

	// Create the queries directory using absolute path
	queriesDir := filepath.Join(projectRoot, "db", "query")
	if err := os.MkdirAll(queriesDir, 0755); err != nil {
		log.Fatalf("Failed to create queries directory: %v", err)
	}

	// Parse the template
	tmpl, err := template.New("sqlc").Funcs(templateFuncs).Parse(sqlcQueryTemplate)
	if err != nil {
		log.Fatalf("Failed to parse template: %v", err)
	}

	// Generate a query file for each table
	for _, table := range sr.Tables {
		// Determine the primary key column (assuming first column or id column)
		primaryKeyColumn := table.Columns[0].Name
		for _, col := range table.Columns {
			if col.Name == "id" {
				primaryKeyColumn = "id"
				break
			}
		}

		// Prepare non-primary key columns
		var nonPrimaryKeyColumns []Column
		for _, col := range table.Columns {
			// Still identify auto-increment fields, but we'll include them in all operations
			isAutoIncrement := strings.Contains(col.DataType, "serial") ||
				(col.Name == "id" && (strings.Contains(col.DataType, "int") || col.DataType == "bigint"))

			// Add column to appropriate lists
			if col.Name != primaryKeyColumn {
				nonPrimaryKeyColumns = append(nonPrimaryKeyColumns, col)
			}

			// Set the flag but don't filter based on it
			col.IsAutoIncrement = isAutoIncrement
		}

		// Prepare the template data
		data := TemplateData{
			TableName:               table.Name,
			TableNameCamel:          snakeToCamel(table.Name),
			PrimaryKeyColumn:        primaryKeyColumn,
			Columns:                 table.Columns,
			NonPrimaryKeyColumns:    nonPrimaryKeyColumns,
			NonAutoIncrementColumns: table.Columns, // Use all columns
		}

		// Create the query file
		queryFile := filepath.Join(queriesDir, fmt.Sprintf("%s.sql", table.Name))
		file, err := os.Create(queryFile)
		if err != nil {
			log.Fatalf("Failed to create query file %s: %v", queryFile, err)
		}

		// Execute the template
		if err := tmpl.Execute(file, data); err != nil {
			file.Close()
			log.Fatalf("Failed to execute template for table %s: %v", table.Name, err)
		}
		file.Close()

		// Verify the file was created successfully
		if _, err := os.Stat(queryFile); os.IsNotExist(err) {
			log.Fatalf("Failed to create query file at %s: file does not exist after creation", queryFile)
		}

		// Check file size to ensure content was written
		fileInfo, err := os.Stat(queryFile)
		if err != nil {
			log.Fatalf("Failed to verify query file at %s: %v", queryFile, err)
		}
		if fileInfo.Size() == 0 {
			log.Fatalf("Query file at %s was created but contains no data", queryFile)
		}

		fmt.Printf("Generated query file for table: %s\n", table.Name)
	}
	fmt.Println("All query files generated successfully!")
}
