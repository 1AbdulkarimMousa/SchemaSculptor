package agent

// GetTable returns a table by name
func (sr *SchemaRegistry) GetTable(name string) (*Table, bool) {
	for i := range sr.Tables {
		if sr.Tables[i].Name == name {
			return &sr.Tables[i], true
		}
	}
	return nil, false
}

// GetColumn returns a column by table and column name
func (sr *SchemaRegistry) GetColumn(tableName, columnName string) (*Column, bool) {
	table, found := sr.GetTable(tableName)
	if !found {
		return nil, false
	}

	for i := range table.Columns {
		if table.Columns[i].Name == columnName {
			return &table.Columns[i], true
		}
	}
	return nil, false
}

// GetReferencingColumns returns all columns that reference a given table and column
func (sr *SchemaRegistry) GetReferencingColumns(tableName, columnName string) []struct {
	Table  *Table
	Column *Column
} {
	var result []struct {
		Table  *Table
		Column *Column
	}

	for i := range sr.Tables {
		table := &sr.Tables[i]
		for j := range table.Columns {
			column := &table.Columns[j]
			for _, ref := range column.References {
				if ref.Table == tableName && ref.Column == columnName {
					result = append(result, struct {
						Table  *Table
						Column *Column
					}{
						Table:  table,
						Column: column,
					})
				}
			}
		}
	}

	return result
}
