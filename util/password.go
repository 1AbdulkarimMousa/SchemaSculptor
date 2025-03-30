package util

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

//returns bcrypt hash of the password
func Hash(password string) (string, error) {
	HashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(HashedPassword), nil
}

func RandomHash(password string) string {
	HashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return ""
	}
	return string(HashedPassword)
}

//compares between a given password and a hashedPassword
func Check(password string, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
