// Package main demonstrates the usage of the secretfetch library
package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/crazywolf132/SecretFetch"
)

// DatabaseConfig holds configuration for database connections including secrets
type DatabaseConfig struct {
	Host     string `secret:"env:DB_HOST"`
	Port     int    `secret:"env:DB_PORT"`
	Username string `secret:"env:DB_USER"`
	Password string `secret:"env:DB_PASS,aws:db/password"`
}

// Config represents the complete application configuration
type Config struct {
	// Basic string configuration
	Environment string `secret:"env=APP_ENV,fallback=development"`

	// Pattern validation for format checking
	APIKey string `secret:"env:API_KEY,aws:api/key,required,pattern=^[A-Za-z0-9]{32}$"`

	// Base64 encoded secret
	Certificate string `secret:"env=TLS_CERT,base64"`

	// JSON configuration stored as a single secret
	Database DatabaseConfig `secret:"aws=prod/db/config,json"`

	// Numbers with range validation
	MaxConnections int `secret:"env=MAX_CONNS,fallback=100,pattern=^[1-9][0-9]{0,3}$"`

	// Duration with custom TTL
	SessionTimeout time.Duration `secret:"env=SESSION_TIMEOUT,fallback=24h,ttl=5m"`

	// Slice of bytes for raw data
	RawData []byte `secret:"env=RAW_DATA"`

	// Additional fields
	Debug    bool   `secret:"env:DEBUG"`
}

func main() {
	// Create an empty config struct
	cfg := &Config{}

	// Create options for customized behavior
	opts := &secretfetch.Options{
		AWS: &aws.Config{
			Region: "us-west-2",
		},
		Validators: map[string]secretfetch.ValidationFunc{
			"api_key": func(s string) error {
				if len(s) != 32 {
					return fmt.Errorf("API key must be 32 characters long")
				}
				return nil
			},
		},
		Transformers: map[string]secretfetch.TransformFunc{
			"uppercase": func(s string) (string, error) {
				return strings.ToUpper(s), nil
			},
		},
	}

	// Populate all secrets with advanced features
	ctx := context.Background()
	if err := secretfetch.Fetch(ctx, cfg, opts); err != nil {
		log.Fatalf("Failed to fetch secrets: %v", err)
	}

	// Use your fully populated config!
	fmt.Printf("Environment: %s\n", cfg.Environment)
	fmt.Printf("Database Config: %+v\n", cfg.Database)
	fmt.Printf("Session Timeout: %v\n", cfg.SessionTimeout)
	fmt.Printf("Max Connections: %d\n", cfg.MaxConnections)
	fmt.Printf("Certificate Length: %d bytes\n", len(cfg.Certificate))
	fmt.Printf("Raw Data Length: %d bytes\n", len(cfg.RawData))
}
