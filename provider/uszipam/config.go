package uszipam

import (
	"errors"
	"os"
)

// Config holds the configuration values for the app.
type Config struct {
	APIBaseURL string
	APIKey     string
}

// NewConfig reads environment variables and creates a new Config object.
// It returns an error if any required environment variable is missing.
func NewConfig() (*Config, error) {
	apiBaseURL := getEnv("USZIPAM_API_BASE_URL", "")
	apiKey := getEnv("USZIPAM_API_KEY", "")

	// Check if required environment variables are set
	if apiBaseURL == "" || apiKey == "" {
		return nil, errors.New("missing required environment variables: USZIPAM_API_BASE_URL or USZIPAM_API_KEY")
	}

	return &Config{
		APIBaseURL: apiBaseURL,
		APIKey:     apiKey,
	}, nil
}

// getEnv reads an environment variable or returns the default value if it's not set.
func getEnv(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}
	return value
}
