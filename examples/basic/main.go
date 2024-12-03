package main

import (
	"context"
	"log"

	"github.com/crazywolf132/secretfetch"
)

type Config struct {
	// Simple environment variable
	APIKey string `secret:"API_KEY,required"`
	// Environment variable with fallback
	LogLevel string `secret:"LOG_LEVEL,fallback=info"`
	// Environment variable with validation
	Port string `secret:"PORT,pattern=^[0-9]{4}$"`
}

func main() {
	var config Config
	if err := secretfetch.Fetch(context.Background(), &config, nil); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Printf("API Key length: %d", len(config.APIKey))
	log.Printf("Log Level: %s", config.LogLevel)
	log.Printf("Port: %s", config.Port)
}
