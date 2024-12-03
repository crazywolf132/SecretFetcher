package main

import (
	"context"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/crazywolf132/secretfetch"
)

type DatabaseConfig struct {
	// Full ARN syntax
	Username string `secret:"arn:aws:secretsmanager:us-west-2:123456789012:secret:prod/db/credentials:username"`
	Password string `secret:"arn:aws:secretsmanager:us-west-2:123456789012:secret:prod/db/credentials:password"`
	
	// Short AWS syntax
	Host     string `secret:"aws=prod/db/host"`
	Port     string `secret:"aws=prod/db/port"`
	
	// Environment variable with AWS fallback
	Database string `secret:"DB_NAME,aws=prod/db/name"`
}

func main() {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	// Configure SecretFetch options
	opts := &secretfetch.Options{
		AWS:           &cfg,
		CacheDuration: 5 * time.Minute,
		PreloadARNs:   true, // Preload secrets for better performance
		SecureCache:   true, // Use secure memory for caching sensitive data
	}

	var dbConfig DatabaseConfig
	if err := secretfetch.Fetch(context.Background(), &dbConfig, opts); err != nil {
		log.Fatalf("Failed to load database configuration: %v", err)
	}

	log.Printf("Database Host: %s", dbConfig.Host)
	log.Printf("Database Port: %s", dbConfig.Port)
	log.Printf("Database Name: %s", dbConfig.Database)
	log.Printf("Username: %s", dbConfig.Username)
	log.Printf("Password length: %d", len(dbConfig.Password))
}
