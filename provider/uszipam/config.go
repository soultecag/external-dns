package uszipam

import (
	"errors"
	"os"

	multierror "github.com/hashicorp/go-multierror"
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

	cfg := &Config{
		APIBaseURL: apiBaseURL,
		APIKey:     apiKey,
	}
	if valid, err := configValid(cfg); !valid {
		return nil, err
	}
	return cfg, nil
}

// getEnv reads an environment variable or returns the default value if it's not set.
func getEnv(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}
	return value
}

func configValid(config *Config) (bool, error) {
	var result error
	// Check if required environment variables are set
	if config.APIBaseURL == "" {
		result = multierror.Append(result, errors.New("missing required environment variables: USZIPAM_API_BASE_URL"))
	}
	// Check if required environment variables are set
	if config.APIKey == "" {
		result = multierror.Append(result, errors.New("missing required environment variables: USZIPAM_API_KEY"))
	}

	if result != nil {
		return false, result
	} else {
		return true, result
	}
}
