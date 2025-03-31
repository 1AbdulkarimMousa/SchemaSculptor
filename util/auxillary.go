package util

import (
	"regexp"
)

var emailRegex *regexp.Regexp

func init() {
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
}

// IsValidEmail checks if an email has a valid format
func IsValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}
