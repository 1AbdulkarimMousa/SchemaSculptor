package agent

import (
	"strings"
	"text/template"
)

// Template for each table's CRUD operations
const sqlcQueryTemplate = `-- name: Get{{ .TableNameCamel }} :one
-- Description: Retrieve a single {{ .TableName }} record by primary key
SELECT 
	*
FROM 
	{{ .TableName }}
WHERE 
	{{ .PrimaryKeyColumn }} = $1
LIMIT 1;

-- name: List{{ .TableNameCamel }}s :many
-- Description: Retrieve all {{ .TableName }} records ordered by primary key
SELECT 
	*
FROM 
	{{ .TableName }}
ORDER BY 
	{{ .PrimaryKeyColumn }};

-- name: Create{{ .TableNameCamel }} :one
-- Description: Insert a new {{ .TableName }} record and return the created record
INSERT INTO 
	{{ .TableName }} (
{{- range $i, $col := .Columns }}
	{{- if $i }}, {{ end }}{{ $col.Name }}
{{- end }}
) 
VALUES (
{{- range $i, $col := .Columns }}
	{{- if $i }}, {{ end }}${{ add $i 1 }}
{{- end }}
)
RETURNING *;

-- name: Update{{ .TableNameCamel }} :one
-- Description: Update a {{ .TableName }} record by primary key and return the updated record
UPDATE 
	{{ .TableName }}
SET {{ range $i, $col := .NonPrimaryKeyColumns }}{{- if $i }}, {{ end }}{{ $col.Name }} = ${{ add $i 2 }}{{ end }}
WHERE 
	{{ .PrimaryKeyColumn }} = $1
RETURNING *;

-- name: Delete{{ .TableNameCamel }} :exec
-- Description: Delete a {{ .TableName }} record by primary key
DELETE FROM 
	{{ .TableName }}
WHERE 
	{{ .PrimaryKeyColumn }} = $1;
`

// TemplateData holds the data for the template
type TemplateData struct {
	TableName               string
	TableNameCamel          string
	PrimaryKeyColumn        string
	Columns                 []Column
	NonPrimaryKeyColumns    []Column
	NonAutoIncrementColumns []Column
}

// Helper function to convert snake_case to CamelCase
func snakeToCamel(s string) string {
	words := strings.Split(s, "_")
	for i := range words {
		words[i] = strings.Title(words[i])
	}
	return strings.Join(words, "")
}

// Helper functions for the template
var templateFuncs = template.FuncMap{
	"add": func(a, b int) int {
		return a + b
	},
}
