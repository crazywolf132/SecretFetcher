// Package main demonstrates the usage of the secretfetch library
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/crazywolf132/secretfetch"
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
	Debug bool `secret:"env:DEBUG"`
}

func main() {
	// Set up environment variables for testing
	os.Setenv("SECRET_ARN", "arn:aws:secretsmanager:region:account:secret:name")
	os.Setenv("DB_HOST", "localhost")
	os.Setenv("DB_PORT", "5432")
	os.Setenv("DB_USER", "admin")

	// Create an empty config struct
	cfg := &DatabaseConfig{}

	// Create options with AWS configuration
	opts := &secretfetch.Options{
		AWS: &aws.Config{
			Region: "us-west-2", // This can also be set via AWS_REGION environment variable
		},
	}

	// Fetch all secrets
	ctx := context.Background()
	if err := secretfetch.Fetch(ctx, cfg, opts); err != nil {
		log.Fatalf("Failed to fetch secrets: %v", err)
	}

	// Use the configuration
	fmt.Printf("Database Configuration:\n")
	fmt.Printf("Host: %s\n", cfg.Host)
	fmt.Printf("Port: %d\n", cfg.Port)
	fmt.Printf("Username: %s\n", cfg.Username)
	fmt.Printf("Password: [REDACTED]\n")
}
