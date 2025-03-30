package util

import (
	"strings"
)

func CamelCase(name *string) {
	parts := strings.Split(*name, "_")
	for i := range parts {
		parts[i] = strings.Title(parts[i])
		if parts[i] == "Id" {
			parts[i] = "ID"
		}
	}
	if parts != nil {
		*name = strings.Join(parts, "")
	}
}
