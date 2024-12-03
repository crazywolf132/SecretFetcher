package main

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/crazywolf132/secretfetch"
)

type AppConfig struct {
	// Environment variables with validation
	Environment string `secret:"APP_ENV,pattern=^(dev|staging|prod)$"`
	Debug       string `secret:"DEBUG,transform=bool"`

	// AWS Secrets with base64 encoding and validation
	APIKeys struct {
		Stripe   string `secret:"arn:aws:secretsmanager:us-west-2:123456789012:secret:prod/api/stripe:key,base64,pattern=^sk_.*$"`
		SendGrid string `secret:"arn:aws:secretsmanager:us-west-2:123456789012:secret:prod/api/sendgrid:key,base64"`
	}

	// Custom validation and transformation
	RateLimit string `secret:"RATE_LIMIT,validate=rateLimit,transform=int"`
}

func main() {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	// Custom validation function
	rateLimitValidator := func(value string) error {
		limit := regexp.MustCompile(`^[1-9][0-9]*$`)
		if !limit.MatchString(value) {
			return fmt.Errorf("rate limit must be a positive integer")
		}
		return nil
	}

	// Configure SecretFetch options with custom validators
	opts := &secretfetch.Options{
		AWS:           &cfg,
		CacheDuration: 5 * time.Minute,
		Validators: map[string]secretfetch.ValidationFunc{
			"rateLimit": rateLimitValidator,
		},
		SecureCache: true,
	}

	var config AppConfig
	if err := secretfetch.Fetch(context.Background(), &config, opts); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Printf("Environment: %s", config.Environment)
	log.Printf("Debug Mode: %s", config.Debug)
	log.Printf("Rate Limit: %s", config.RateLimit)
	log.Printf("Stripe Key length: %d", len(config.APIKeys.Stripe))
	log.Printf("SendGrid Key length: %d", len(config.APIKeys.SendGrid))
}
