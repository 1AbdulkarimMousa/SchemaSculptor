package agent

import (
	"fmt"
)

// PrintSchema prints the schema information for debugging
func (sr *SchemaRegistry) PrintSchema() {
	for _, table := range sr.Tables {
		fmt.Printf("Table: %s\n", table.Name)
		for _, column := range table.Columns {
			fmt.Printf("  Column: %s (%s, Nullable: %s)\n",
				column.Name, column.DataType, column.IsNullable)

			if len(column.References) > 0 {
				fmt.Printf("    References:\n")
				for _, ref := range column.References {
					fmt.Printf("      %s.%s\n", ref.Table, ref.Column)
				}
			}
		}
		fmt.Println()
	}
}
