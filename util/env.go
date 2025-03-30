package util

import (
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Configuration variables
var (
	// Admin
	AdminPassword string

	// Database
	DBHost string
	DBPort string
	DBName string
	DBUser string
	DBPass string
	DBSSl  string

	// HTTP server
	HTTPPort string
	HTTPIP   string

	// SMTP
	SMTPHost string
	SMTPPort string
	SMTPUser string
	SMTPPass string

	// Paseto encryption key
	PasetoKey string
)

// loadDotEnv loads environment variables from .env files
func loadDotEnv(filenames ...string) error {
	if len(filenames) == 0 {
		return godotenv.Load()
	}
	return godotenv.Load(filenames...)
}

// init loads the .env file(s)
func init() {
	if err := loadDotEnv(); err != nil {
		// Continue even if .env file is not found
		// Variables can still be set through environment
	}
}

// init initializes all configuration variables
func init() {
	// Admin
	AdminPassword = GetEnv("ADMIN_PASSWORD", "")

	// Database
	DBHost = GetEnv("DB_HOST", "localhost")
	DBPort = GetEnv("DB_PORT", "5432")
	DBName = GetEnv("DB_NAME", "valueflow")
	DBUser = GetEnv("DB_USER", "valueflow")
	DBPass = GetEnv("DB_PASS", "valueflow")
	DBSSl = GetEnv("DB_SSL", "disable")

	// HTTP server
	HTTPPort = GetEnv("HTTP_PORT", "8000")
	HTTPIP = GetEnv("HTTP_IP", "0.0.0.0")

	// SMTP
	SMTPHost = GetEnv("SMTP_HOST", "")
	SMTPPort = GetEnv("SMTP_PORT", "587")
	SMTPUser = GetEnv("SMTP_USER", "")
	SMTPPass = GetEnv("SMTP_PASS", "")

	// Paseto
	PasetoKey = GetEnv("PASETO_KEY", "")
}

// LoadEnv is a wrapper to explicitly load environment variables from specified files
func LoadEnv(filenames ...string) error {
	return loadDotEnv(filenames...)
}

// GetEnv retrieves an environment variable by name.
// If the variable is not found, it returns the fallback value.
func GetEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// GetEnvBool retrieves a boolean environment variable.
// It returns the fallback value if the variable doesn't exist or cannot be parsed as a boolean.
func GetEnvBool(key string, fallback bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return fallback
}

// GetEnvInt retrieves an integer environment variable.
// It returns the fallback value if the variable doesn't exist or cannot be parsed as an integer.
func GetEnvInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return fallback
}

// GetEnvFloat retrieves a float environment variable.
// It returns the fallback value if the variable doesn't exist or cannot be parsed as a float.
func GetEnvFloat(key string, fallback float64) float64 {
	if value, exists := os.LookupEnv(key); exists {
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			return f
		}
	}
	return fallback
}

// GetEnvDuration retrieves a time.Duration environment variable.
// It returns the fallback value if the variable doesn't exist or cannot be parsed as a duration.
func GetEnvDuration(key string, fallback time.Duration) time.Duration {
	if value, exists := os.LookupEnv(key); exists {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return fallback
}
