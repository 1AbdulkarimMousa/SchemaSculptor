package agent

// Reference represents a foreign key reference
type Reference struct {
	Table  string `json:"table"`
	Column string `json:"column"`
}

// Column represents a database column with its properties
type Column struct {
	Name            string      `json:"column_name"`
	DataType        string      `json:"data_type"`
	IsNullable      string      `json:"is_nullable"`
	References      []Reference `json:"references"`
	IsAutoIncrement bool        `json:"-"` // Used for code generation, not stored in DB
}

// Table represents a database table with its columns
type Table struct {
	Name    string   `json:"table_name"`
	Columns []Column `json:"columns"`
}
