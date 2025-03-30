package agent

import (
	"context"
	"encoding/json"
	"fmt"
)

// LoadSchema loads the database schema
func (sr *SchemaRegistry) LoadSchema(ctx context.Context) error {
	const schemaQuery = `
	-- Return database schema as JSON with table and column information including foreign keys
	SELECT row_to_json(t)
	FROM (
	  -- For each table, get its columns and their properties
	  SELECT 
		c.table_name,
		json_agg(
		  json_build_object(
			'column_name', c.column_name,
			'data_type', c.data_type,
			'is_nullable', c.is_nullable,
			-- Get foreign key references for this column (if any)
			'references', (
			  -- Subquery to find all distinct foreign key references
			  SELECT 
				CASE 
				  WHEN COUNT(*) > 0 THEN 
					-- Use DISTINCT to remove duplicate references
					json_agg(
					  DISTINCT jsonb_build_object(
						'table', ccu.table_name,
						'column', ccu.column_name
					  )
					)
				  ELSE NULL 
				END
			  FROM 
				-- Join tables needed for foreign key information
				information_schema.table_constraints tc
				JOIN information_schema.key_column_usage kcu
				  ON tc.constraint_name = kcu.constraint_name
				  AND tc.table_schema = kcu.table_schema
				JOIN information_schema.constraint_column_usage ccu
				  ON ccu.constraint_name = tc.constraint_name
			  WHERE 
				-- Only include foreign keys
				tc.constraint_type = 'FOREIGN KEY'
				-- That reference this specific column
				AND kcu.table_name = c.table_name
				AND kcu.column_name = c.column_name
				AND tc.table_schema = 'public'
			)
		  ) ORDER BY c.ordinal_position
		) AS columns
	  FROM 
		information_schema.columns c
	  WHERE 
		c.table_schema = 'public'
	  GROUP BY 
		c.table_name
	) t;
	`

	// Execute the query
	rows, err := sr.db.QueryContext(ctx, schemaQuery)
	if err != nil {
		return fmt.Errorf("failed to execute schema query: %w", err)
	}
	defer rows.Close()

	// Process the results
	var tables []Table
	for rows.Next() {
		var jsonData string
		if err := rows.Scan(&jsonData); err != nil {
			return fmt.Errorf("failed to scan row: %w", err)
		}

		var table Table
		if err := json.Unmarshal([]byte(jsonData), &table); err != nil {
			return fmt.Errorf("failed to unmarshal table data: %w", err)
		}

		tables = append(tables, table)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating rows: %w", err)
	}

	sr.Tables = tables
	return nil
}
