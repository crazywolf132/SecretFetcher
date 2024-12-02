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

// SecretsManagerClient defines the interface for AWS Secrets Manager operations
type SecretsManagerClient interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

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
	// PreloadARNs indicates whether to preload secrets from ARNs
	PreloadARNs bool
	// SecretsManager is the AWS Secrets Manager client
	SecretsManager SecretsManagerClient
	// OnSecretAccess is called whenever a secret is accessed
	OnSecretAccess func(ctx context.Context, secretID string)
	// MetricsCollector collects security metrics
	MetricsCollector SecurityMetricsCollector
	// SecureCache indicates whether to use secure memory for caching
	SecureCache bool
	cacheMu     sync.RWMutex
	cache       map[string]*cachedValue
}

// SecurityMetricsCollector defines the interface for collecting security metrics
type SecurityMetricsCollector interface {
	// OnSecretAccess is called when a secret is accessed
	OnSecretAccess(metric SecretAccessMetric)
}

// SecretAccessMetric contains information about a secret access event
type SecretAccessMetric struct {
	// SecretID is the identifier of the secret
	SecretID string
	// AccessTime is when the secret was accessed
	AccessTime time.Time
	// Source indicates where the secret came from (AWS, env, etc.)
	Source string
	// CacheHit indicates if the secret was served from cache
	CacheHit bool
}

// secureValue represents a secret value with secure memory handling
type secureValue struct {
	value []byte
	mu    sync.RWMutex
}

func (s *secureValue) Set(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.value = make([]byte, len(value))
	copy(s.value, value)
}

func (s *secureValue) Get() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return string(s.value)
}

func (s *secureValue) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.value {
		s.value[i] = 0
	}
	s.value = nil
}

// cachedValue represents a cached secret value
type cachedValue struct {
	value      interface{}
	expiration time.Time
	secure     *secureValue
}

func (cv *cachedValue) String() string {
	if cv.secure != nil {
		return cv.secure.Get()
	}
	if str, ok := cv.value.(string); ok {
		return str
	}
	return fmt.Sprintf("%v", cv.value)
}

func (cv *cachedValue) Clear() {
	if cv.secure != nil {
		cv.secure.Clear()
	}
	cv.value = nil
}

func newCachedValue(value string, expiration time.Time, secure bool) *cachedValue {
	cv := &cachedValue{
		expiration: expiration,
	}
	if secure {
		cv.secure = &secureValue{}
		cv.secure.Set(value)
	} else {
		cv.value = value
	}
	return cv
}

// OptionsKey is the key for storing Options in the context
var optionsKey = "secretfetch-options"

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
	required   bool
}

var (
	secretsCache map[string]string = make(map[string]string)
	secretsMu    sync.RWMutex
	secretsOnce  sync.Once
)

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
				s.required = true
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

	// Store options in context
	ctx = context.WithValue(ctx, optionsKey, opts)

	// Preload secrets from ARNs if enabled
	if opts.PreloadARNs {
		if err := preloadSecretsFromARNs(ctx, opts); err != nil {
			return fmt.Errorf("failed to preload secrets from ARNs: %w", err)
		}
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
	defer s.mu.RUnlock()

	// Generate a unique cache key for this secret
	cacheKey := s.cacheKey()

	// Check if value exists in cache and is not expired
	opts.cacheMu.RLock()
	cached, ok := opts.cache[cacheKey]
	opts.cacheMu.RUnlock()
	if ok && time.Now().Before(cached.expiration) {
		if opts.MetricsCollector != nil {
			opts.MetricsCollector.OnSecretAccess(SecretAccessMetric{
				SecretID:   s.awsKey,
				AccessTime: time.Now(),
				Source:     "cache",
				CacheHit:   true,
			})
		}
		return cached.String(), nil
	}

	var lastErr error

	// Try AWS first if enabled
	if opts != nil && opts.AWS != nil && s.awsKey != "" {
		awsValue, err := s.getFromAWS(ctx, opts.AWS)
		if err != nil {
			if s.required {
				return "", fmt.Errorf("failed to get value from AWS for required field %s: %w", s.field.Name, err)
			}
			lastErr = fmt.Errorf("failed to get value from AWS: %w", err)
		} else {
			// Process and validate the value
			processedValue, err := s.processValue(awsValue)
			if err != nil {
				if s.required {
					return "", err
				}
				lastErr = err
			} else {
				// Cache the processed value if caching is enabled
				if opts.CacheDuration > 0 {
					expiration := time.Now().Add(opts.CacheDuration)
					cv := newCachedValue(processedValue, expiration, opts.SecureCache)
					opts.cacheMu.Lock()
					opts.cache[cacheKey] = cv
					opts.cacheMu.Unlock()
				}
				if opts.MetricsCollector != nil {
					opts.MetricsCollector.OnSecretAccess(SecretAccessMetric{
						SecretID:   s.awsKey,
						AccessTime: time.Now(),
						Source:     "aws",
						CacheHit:   false,
					})
				}
				return processedValue, nil
			}
		}
	}

	// Try environment variable if AWS lookup failed or was disabled
	if s.envKey != "" {
		if value, ok := os.LookupEnv(s.envKey); ok {
			// Process and validate the value
			processedValue, err := s.processValue(value)
			if err != nil {
				if s.required {
					return "", err
				}
				lastErr = err
			} else {
				// Cache the processed value if caching is enabled
				if opts.CacheDuration > 0 {
					expiration := time.Now().Add(opts.CacheDuration)
					cv := newCachedValue(processedValue, expiration, opts.SecureCache)
					opts.cacheMu.Lock()
					opts.cache[cacheKey] = cv
					opts.cacheMu.Unlock()
				}
				if opts.MetricsCollector != nil {
					opts.MetricsCollector.OnSecretAccess(SecretAccessMetric{
						SecretID:   s.awsKey,
						AccessTime: time.Now(),
						Source:     "env",
						CacheHit:   false,
					})
				}
				return processedValue, nil
			}
		}
	}

	// Use fallback value if no other source provided a value
	if s.fallback != "" {
		// Process and validate the fallback value
		processedValue, err := s.processValue(s.fallback)
		if err != nil {
			if s.required {
				return "", err
			}
			lastErr = err
		} else {
			// Cache the processed fallback value if caching is enabled
			if opts.CacheDuration > 0 {
				expiration := time.Now().Add(opts.CacheDuration)
				cv := newCachedValue(processedValue, expiration, opts.SecureCache)
				opts.cacheMu.Lock()
				opts.cache[cacheKey] = cv
				opts.cacheMu.Unlock()
			}
			if opts.MetricsCollector != nil {
				opts.MetricsCollector.OnSecretAccess(SecretAccessMetric{
					SecretID:   s.awsKey,
					AccessTime: time.Now(),
					Source:     "fallback",
					CacheHit:   false,
				})
			}
			return processedValue, nil
		}
	}

	// If we reach here, no value was found
	if s.required {
		if lastErr != nil {
			return "", fmt.Errorf("no value found for required secret %s: %w", s.field.Name, lastErr)
		}
		return "", fmt.Errorf("no value found for required secret %s", s.field.Name)
	}

	// For non-required fields, return empty string or last error
	if lastErr != nil {
		return "", lastErr
	}
	return "", nil
}

func (s *secret) getFromAWS(ctx context.Context, awsConfig *aws.Config) (string, error) {
	if s.awsKey == "" {
		return "", nil
	}

	var client SecretsManagerClient
	if opts, ok := ctx.Value(optionsKey).(*Options); ok && opts.SecretsManager != nil {
		client = opts.SecretsManager
	} else {
		cfg := awsConfig
		if cfg == nil {
			defaultCfg, err := config.LoadDefaultConfig(ctx)
			if err != nil {
				return "", fmt.Errorf("unable to load AWS config: %v", err)
			}
			cfg = &defaultCfg
		}
		client = secretsmanager.NewFromConfig(*cfg)
	}

	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(s.awsKey),
	}

	result, err := client.GetSecretValue(ctx, input)
	if err != nil {
		return "", fmt.Errorf("error fetching secret %s: %v", s.awsKey, err)
	}

	if result.SecretString != nil {
		return *result.SecretString, nil
	}

	if result.SecretBinary != nil {
		return string(result.SecretBinary), nil
	}

	return "", fmt.Errorf("no secret value found for %s", s.awsKey)
}

// FetchAndValidate is an alias for Fetch to maintain backward compatibility
func FetchAndValidate(ctx context.Context, v interface{}) error {
	return Fetch(ctx, v, nil)
}

// preloadSecretsFromARNs fetches secrets from AWS Secrets Manager and caches them
func preloadSecretsFromARNs(ctx context.Context, opts *Options) error {
	arns := getSecretARNs()
	if len(arns) == 0 {
		return fmt.Errorf("no secret ARNs found in environment variables SECRET_ARNS or SECRET_ARN")
	}

	var client SecretsManagerClient
	if opts.SecretsManager != nil {
		client = opts.SecretsManager
	} else {
		cfg := opts.AWS
		if cfg == nil {
			defaultCfg, err := config.LoadDefaultConfig(ctx)
			if err != nil {
				return fmt.Errorf("unable to load AWS config: %v", err)
			}
			cfg = &defaultCfg
		}
		client = secretsmanager.NewFromConfig(*cfg)
	}

	for _, arn := range arns {
		input := &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(arn),
		}

		result, err := client.GetSecretValue(ctx, input)
		if err != nil {
			return fmt.Errorf("error fetching secret %s: %v", arn, err)
		}

		if result.SecretString == nil && result.SecretBinary == nil {
			return fmt.Errorf("no secret value found for %s", arn)
		}

		// Cache the secret
		cacheKey := "aws:" + arn
		expiration := time.Now().Add(opts.CacheDuration)
		var cv *cachedValue
		if result.SecretString != nil {
			cv = newCachedValue(*result.SecretString, expiration, opts.SecureCache)
		} else {
			cv = newCachedValue(string(result.SecretBinary), expiration, opts.SecureCache)
		}
		opts.cacheMu.Lock()
		opts.cache[cacheKey] = cv
		opts.cacheMu.Unlock()
	}

	return nil
}

// getSecretARNs returns a list of secret ARNs from environment variables
func getSecretARNs() []string {
	arns := os.Getenv("SECRET_ARNS")
	if arns == "" {
		arns = os.Getenv("SECRET_ARN")
	}
	if arns == "" {
		return nil
	}
	arnsList := strings.Split(arns, ",")
	for i := range arnsList {
		arnsList[i] = strings.TrimSpace(arnsList[i])
	}
	return arnsList
}
