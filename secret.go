// Package secretfetch provides a simple and flexible way to manage secrets from various sources
// including AWS Secrets Manager and environment variables. It supports automatic type conversion,
// validation, and transformation of secret values.
package secretfetch

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// Options holds configuration options for fetching secrets
type Options struct {
	// AWS is the AWS configuration
	AWS *aws.Config
	// Validators is a map of named validation functions
	Validators map[string]ValidationFunc
	// Transformers is a map of named transformation functions
	Transformers map[string]TransformFunc
	// CacheDuration specifies how long to cache values for
	CacheDuration time.Duration
	cacheMu       sync.RWMutex
	cache         map[string]*cachedValue
}

// ValidationFunc is a function type for custom validation
type ValidationFunc func(string) error

// TransformFunc is a function type for custom transformation
type TransformFunc func(string) (string, error)

// ValidationError represents an error that occurred during validation
type ValidationError struct {
	Field string
	Err   error
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation failed for field %q: %v", e.Field, e.Err)
}

type secret struct {
	pattern    *regexp.Regexp
	isBase64   bool
	isJSON     bool
	isYAML     bool
	value      string
	ttl        time.Duration
	fetchedAt  time.Time
	validation func(string) error
	transform  func(string) (string, error)
	field      reflect.StructField
	envKey     string
	fallback   string
	awsKey     string
	mu         sync.RWMutex
	cache      *cachedValue
}

type cachedValue struct {
	value      string
	expiration time.Time
}

func validatePattern(value, pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern %q: %v", pattern, err)
	}
	if !re.MatchString(value) {
		return fmt.Errorf("value %q does not match pattern %q", value, pattern)
	}
	return nil
}

func parseTag(field reflect.StructField, opts *Options) (*secret, error) {
	tag := field.Tag.Get("secret")
	if tag == "" {
		return nil, fmt.Errorf("no secret tag found for field %s", field.Name)
	}

	s := &secret{
		field: field,
	}

	// Split by comma but handle special cases for pattern
	var parts []string
	var current string
	var inPattern bool
	var depth int

	for i := 0; i < len(tag); i++ {
		switch tag[i] {
		case '{':
			depth++
			current += string(tag[i])
		case '}':
			depth--
			current += string(tag[i])
		case ',':
			if depth == 0 && !inPattern {
				if current != "" {
					parts = append(parts, strings.TrimSpace(current))
				}
				current = ""
			} else {
				current += string(tag[i])
			}
		case '=':
			if strings.HasPrefix(tag[i:], "=pattern=") {
				inPattern = true
			}
			current += string(tag[i])
		default:
			current += string(tag[i])
		}
	}

	if current != "" {
		parts = append(parts, strings.TrimSpace(current))
	}

	for _, part := range parts {
		if strings.Contains(part, "=") {
			kv := strings.SplitN(part, "=", 2)
			key := strings.TrimSpace(kv[0])
			value := strings.TrimSpace(kv[1])

			switch key {
			case "env":
				s.envKey = value
			case "aws":
				s.awsKey = value
			case "pattern":
				re, err := regexp.Compile(value)
				if err != nil {
					return nil, fmt.Errorf("invalid pattern %q: %w", value, err)
				}
				s.pattern = re
			case "ttl":
				ttl, err := time.ParseDuration(value)
				if err != nil {
					return nil, fmt.Errorf("invalid ttl %q: %w", value, err)
				}
				s.ttl = ttl
			case "fallback":
				s.fallback = value
			case "validate":
				if opts != nil && opts.Validators != nil {
					if validator, ok := opts.Validators[value]; ok {
						s.validation = validator
					} else {
						return nil, fmt.Errorf("unknown validator %q", value)
					}
				}
			case "transform":
				if opts != nil && opts.Transformers != nil {
					if transformer, ok := opts.Transformers[value]; ok {
						s.transform = transformer
					} else {
						return nil, fmt.Errorf("unknown transformer %q", value)
					}
				}
			case "base64":
				if value == "true" {
					s.isBase64 = true
				}
			case "json":
				if value == "true" {
					s.isJSON = true
				}
			case "yaml":
				if value == "true" {
					s.isYAML = true
				}
			default:
				return nil, fmt.Errorf("unknown key %q in secret tag", key)
			}
		} else {
			switch strings.TrimSpace(part) {
			case "required":
				// Required is handled during Get
			case "base64":
				s.isBase64 = true
			case "json":
				s.isJSON = true
			case "yaml":
				s.isYAML = true
			default:
				return nil, fmt.Errorf("unknown option %q in secret tag", part)
			}
		}
	}

	return s, nil
}

func (s *secret) processValue(value string) (string, error) {
	// Base64 decode if needed
	if s.isBase64 {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return "", &ValidationError{
				Field: s.field.Name,
				Err:   fmt.Errorf("failed to decode base64: %w", err),
			}
		}
		value = string(decoded)
	}

	// Validate pattern if needed
	if s.pattern != nil {
		if err := validatePattern(value, s.pattern.String()); err != nil {
			return "", &ValidationError{
				Field: s.field.Name,
				Err:   err,
			}
		}
	}

	// Run custom validation if needed
	if s.validation != nil {
		if err := s.validation(value); err != nil {
			return "", &ValidationError{
				Field: s.field.Name,
				Err:   fmt.Errorf("validation failed: %w", err),
			}
		}
	}

	// Transform if needed
	if s.transform != nil {
		transformed, err := s.transform(value)
		if err != nil {
			return "", &ValidationError{
				Field: s.field.Name,
				Err:   fmt.Errorf("transformation failed: %w", err),
			}
		}
		value = transformed
	}

	return value, nil
}

// Fetch retrieves secrets for the given struct
func Fetch(ctx context.Context, v interface{}, opts *Options) error {
	if opts == nil {
		opts = &Options{
			Validators:   make(map[string]ValidationFunc),
			Transformers: make(map[string]TransformFunc),
			cache:        make(map[string]*cachedValue),
		}
	} else if opts.cache == nil {
		opts.cache = make(map[string]*cachedValue)
	}

	value := reflect.ValueOf(v)
	if value.Kind() != reflect.Ptr {
		return fmt.Errorf("v must be a pointer to a struct")
	}

	value = value.Elem()
	if value.Kind() != reflect.Struct {
		return fmt.Errorf("v must be a pointer to a struct")
	}

	typ := value.Type()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if !field.CanSet() {
			continue
		}

		structField := typ.Field(i)
		s, err := parseTag(structField, opts)
		if err != nil {
			return fmt.Errorf("invalid tag for field %s: %w", structField.Name, err)
		}

		// Get the secret value
		val, err := s.Get(ctx, opts)
		if err != nil {
			return err
		}

		// Set the value
		switch field.Kind() {
		case reflect.String:
			field.SetString(val)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if i, err := strconv.ParseInt(val, 10, 64); err == nil {
				field.SetInt(i)
			} else {
				return &ValidationError{
					Field: structField.Name,
					Err:   fmt.Errorf("failed to convert %q to integer: %w", val, err),
				}
			}
		case reflect.Bool:
			if b, err := strconv.ParseBool(val); err == nil {
				field.SetBool(b)
			} else {
				return &ValidationError{
					Field: structField.Name,
					Err:   fmt.Errorf("failed to convert %q to boolean: %w", val, err),
				}
			}
		default:
			return fmt.Errorf("unsupported field type %v", field.Kind())
		}
	}

	return nil
}

// cacheKey generates a unique key for caching based on environment key, AWS key, and field name
func (s *secret) cacheKey() string {
	return fmt.Sprintf("env:%s|aws:%s|field:%s", s.envKey, s.awsKey, s.field.Name)
}

// Get retrieves the secret value with the given options. It implements a multi-tiered
// lookup strategy:
// 1. Check cache if available
// 2. Try AWS Secrets Manager if configured
// 3. Check environment variables
// 4. Use fallback value if provided
// The retrieved value is then processed (validated, transformed) and cached if caching is enabled.
func (s *secret) Get(ctx context.Context, opts *Options) (string, error) {
	s.mu.RLock()

	// Generate a unique cache key for this secret
	cacheKey := s.cacheKey()

	// Check if value exists in cache and is not expired
	opts.cacheMu.RLock()
	cached, ok := opts.cache[cacheKey]
	if ok && time.Now().Before(cached.expiration) {
		value := cached.value
		opts.cacheMu.RUnlock()
		return value, nil
	}
	opts.cacheMu.RUnlock()

	// Try AWS first if enabled
	if opts != nil && opts.AWS != nil && s.awsKey != "" {
		awsValue, err := s.getFromAWS(ctx, opts.AWS)
		if err != nil {
			return "", fmt.Errorf("failed to get value from AWS: %w", err)
		}
		if awsValue != "" {
			// Process and validate the value
			processedValue, err := s.processValue(awsValue)
			if err != nil {
				return "", err
			}

			// Cache the processed value if caching is enabled
			if opts.CacheDuration > 0 {
				opts.cacheMu.Lock()
				opts.cache[cacheKey] = &cachedValue{
					value:      processedValue,
					expiration: time.Now().Add(opts.CacheDuration),
				}
				opts.cacheMu.Unlock()
			}

			return processedValue, nil
		}
	}

	// Try environment variable if AWS lookup failed or was disabled
	if s.envKey != "" {
		if value := os.Getenv(s.envKey); value != "" {
			// Process and validate the value
			processedValue, err := s.processValue(value)
			if err != nil {
				return "", err
			}

			// Cache the processed value if caching is enabled
			if opts.CacheDuration > 0 {
				opts.cacheMu.Lock()
				opts.cache[cacheKey] = &cachedValue{
					value:      processedValue,
					expiration: time.Now().Add(opts.CacheDuration),
				}
				opts.cacheMu.Unlock()
			}

			return processedValue, nil
		}
	}

	// Use fallback value if no other source provided a value
	if s.fallback != "" {
		// Process and validate the fallback value
		processedValue, err := s.processValue(s.fallback)
		if err != nil {
			return "", err
		}

		// Cache the processed fallback value if caching is enabled
		if opts.CacheDuration > 0 {
			opts.cacheMu.Lock()
			opts.cache[cacheKey] = &cachedValue{
				value:      processedValue,
				expiration: time.Now().Add(opts.CacheDuration),
			}
			opts.cacheMu.Unlock()
		}

		return processedValue, nil
	}

	return "", fmt.Errorf("no value found for secret %s", s.field.Name)
}

func (s *secret) getFromAWS(ctx context.Context, awsConfig *aws.Config) (string, error) {
	cfg, err := config.LoadDefaultConfig(ctx, func(o *config.LoadOptions) error {
		o.Region = awsConfig.Region
		o.Credentials = awsConfig.Credentials
		return nil
	})
	if err != nil {
		return "", err
	}

	client := secretsmanager.NewFromConfig(cfg)
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(s.awsKey),
	}
	if result, err := client.GetSecretValue(ctx, input); err == nil {
		return *result.SecretString, nil
	}
	return "", err
}

// FetchAndValidate is an alias for Fetch to maintain backward compatibility
func FetchAndValidate(ctx context.Context, v interface{}) error {
	return Fetch(ctx, v, nil)
}
