package secretfetch

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfig represents a comprehensive test configuration structure that covers
// all supported secret types and features:
// - Basic type conversion (string, int, bool, duration)
// - Pattern validation
// - Required fields
// - Base64 encoding/decoding
// - JSON parsing
type TestConfig struct {
	// Basic types with type conversion
	StringValue   string        `secret:"env=TEST_STRING,fallback=default"`
	IntValue      int           `secret:"env=TEST_INT,fallback=42"`
	BoolValue     bool          `secret:"env=TEST_BOOL,fallback=true"`
	DurationValue time.Duration `secret:"env=TEST_DURATION,fallback=1h"`

	// Validation features
	Pattern  string `secret:"env=TEST_PATTERN,pattern=^[A-Z]{3}$,fallback=ABC"`
	Required string `secret:"env=TEST_REQUIRED,required"`

	// Advanced encoding features
	Base64Value string `secret:"env=TEST_BASE64,base64"`
	JSONStruct  struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	} `secret:"env=TEST_JSON,json"`
}

// TestBase64Decoding verifies the library's ability to handle base64-encoded secrets.
// It tests both valid and invalid base64 strings to ensure proper error handling.
func TestBase64Decoding(t *testing.T) {
	type Config struct {
		EncodedSecret string `secret:"env=ENCODED_SECRET,base64=true"`
	}

	originalText := "hello world"
	encodedText := base64.StdEncoding.EncodeToString([]byte(originalText))
	os.Setenv("ENCODED_SECRET", encodedText)
	defer os.Unsetenv("ENCODED_SECRET")

	var cfg Config
	err := Fetch(context.Background(), &cfg, &Options{})
	require.NoError(t, err)
	assert.Equal(t, originalText, cfg.EncodedSecret)

	// Test invalid base64
	os.Setenv("ENCODED_SECRET", "invalid-base64")
	err = Fetch(context.Background(), &cfg, &Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode base64")
}

// TestPatternValidation verifies the pattern validation feature using email and username
// patterns as examples. It tests both valid and invalid inputs to ensure the validation
// logic works correctly.
func TestPatternValidation(t *testing.T) {
	type Config struct {
		Email    string `secret:"env=EMAIL,pattern=[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"`
		Username string `secret:"env=USERNAME,pattern=[a-zA-Z0-9_]{3,32}"`
	}

	tests := []struct {
		name      string
		email     string
		username  string
		expectErr bool
	}{
		{
			name:      "valid_values",
			email:     "test@example.com",
			username:  "user123",
			expectErr: false,
		},
		{
			name:      "invalid_email",
			email:     "invalid-email",
			username:  "user123",
			expectErr: true,
		},
		{
			name:      "invalid_username",
			email:     "test@example.com",
			username:  "u",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("EMAIL", tt.email)
			os.Setenv("USERNAME", tt.username)
			defer func() {
				os.Unsetenv("EMAIL")
				os.Unsetenv("USERNAME")
			}()

			var cfg Config
			err := Fetch(context.Background(), &cfg, &Options{})
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "does not match pattern")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.email, cfg.Email)
				assert.Equal(t, tt.username, cfg.Username)
			}
		})
	}
}

// TestAdvancedPatterns verifies complex pattern validation scenarios including:
// - IP address validation
// - Port number validation
// - UUID format validation
// - Version string validation
func TestAdvancedPatterns(t *testing.T) {
	type Config struct {
		IPAddress string `secret:"env=TEST_IP,pattern=((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"`
		Port      string `secret:"env=TEST_PORT,pattern=^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})$"`
		UUID      string `secret:"env=TEST_UUID,pattern=[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"`
		Version   string `secret:"env=TEST_VERSION,pattern=v[0-9]+\\.[0-9]+\\.[0-9]+"`
	}

	validConfig := map[string]string{
		"TEST_IP":      "192.168.1.1",
		"TEST_PORT":    "8080",
		"TEST_UUID":    "123e4567-e89b-4d3c-8456-426614174000",
		"TEST_VERSION": "v1.2.3",
	}

	invalidConfigs := []struct {
		name  string
		key   string
		value string
	}{
		{"invalid_ip", "TEST_IP", "256.256.256.256"},
		{"invalid_port", "TEST_PORT", "65536"},
		{"invalid_uuid", "TEST_UUID", "invalid-uuid"},
		{"invalid_version", "TEST_VERSION", "1.2.3"},
	}

	t.Run("valid_patterns", func(t *testing.T) {
		for k, v := range validConfig {
			os.Setenv(k, v)
		}
		defer func() {
			for k := range validConfig {
				os.Unsetenv(k)
			}
		}()

		var cfg Config
		err := Fetch(context.Background(), &cfg, &Options{})
		require.NoError(t, err)
		assert.Equal(t, validConfig["TEST_IP"], cfg.IPAddress)
		assert.Equal(t, validConfig["TEST_PORT"], cfg.Port)
		assert.Equal(t, validConfig["TEST_UUID"], cfg.UUID)
		assert.Equal(t, validConfig["TEST_VERSION"], cfg.Version)
	})

	for _, ic := range invalidConfigs {
		t.Run(ic.name, func(t *testing.T) {
			for k, v := range validConfig {
				if k != ic.key {
					os.Setenv(k, v)
				}
			}
			os.Setenv(ic.key, ic.value)
			defer func() {
				for k := range validConfig {
					os.Unsetenv(k)
				}
			}()

			var cfg Config
			err := Fetch(context.Background(), &cfg, &Options{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "does not match pattern")
		})
	}
}

// TestCaching verifies the caching mechanism of the library:
// - Initial value retrieval and caching
// - Cache expiration behavior
// - Cache invalidation
// - Concurrent cache access
func TestCaching(t *testing.T) {
	type Config struct {
		Value string `secret:"env=TEST_VALUE"`
	}

	os.Setenv("TEST_VALUE", "initial")
	defer os.Unsetenv("TEST_VALUE")

	var cfg Config
	opts := &Options{
		CacheDuration: 2 * time.Second,
	}

	// First fetch should get "initial"
	err := Fetch(context.Background(), &cfg, opts)
	require.NoError(t, err)
	assert.Equal(t, "initial", cfg.Value)

	// Update env var
	os.Setenv("TEST_VALUE", "updated")

	// Second fetch within cache duration should still get "initial"
	err = Fetch(context.Background(), &cfg, opts)
	require.NoError(t, err)
	assert.Equal(t, "initial", cfg.Value)

	// Wait for cache to expire
	time.Sleep(3 * time.Second)

	// Third fetch after cache expiration should get "updated"
	err = Fetch(context.Background(), &cfg, opts)
	require.NoError(t, err)
	assert.Equal(t, "updated", cfg.Value)
}

// TestSecret_Get verifies the core secret retrieval functionality:
// - Basic environment variable retrieval
// - Pattern validation
// - Base64 decoding
// - Value transformation
// - Custom validation
// - Error handling for various scenarios
func TestSecret_Get(t *testing.T) {
	tests := []struct {
		name      string
		config    interface{}
		envKey    string
		envValue  string
		expectErr bool
		expected  string
	}{
		{
			name: "basic_env_var",
			config: &struct {
				Value string `secret:"env=TEST_VALUE"`
			}{},
			envKey:    "TEST_VALUE",
			envValue:  "test_value",
			expected:  "test_value",
			expectErr: false,
		},
		{
			name: "pattern_validation_success",
			config: &struct {
				Value string `secret:"env=TEST_VALUE,pattern=^[a-z_]+$"`
			}{},
			envKey:    "TEST_VALUE",
			envValue:  "test_value",
			expected:  "test_value",
			expectErr: false,
		},
		{
			name: "pattern_validation_failure",
			config: &struct {
				Value string `secret:"env=TEST_VALUE,pattern=^[a-z_]+$"`
			}{},
			envKey:    "TEST_VALUE",
			envValue:  "TEST_VALUE",
			expectErr: true,
		},
		{
			name: "base64_decode_success",
			config: &struct {
				Value string `secret:"env=TEST_VALUE,base64=true"`
			}{},
			envKey:    "TEST_VALUE",
			envValue:  "aGVsbG8=", // "hello" in base64
			expected:  "hello",
			expectErr: false,
		},
		{
			name: "base64_decode_failure",
			config: &struct {
				Value string `secret:"env=TEST_VALUE,base64=true"`
			}{},
			envKey:    "TEST_VALUE",
			envValue:  "invalid-base64",
			expectErr: true,
		},
		{
			name: "with_transformation",
			config: &struct {
				Value string `secret:"env=TEST_VALUE,transform=uppercase"`
			}{},
			envKey:    "TEST_VALUE",
			envValue:  "test_value",
			expected:  "TEST_VALUE",
			expectErr: false,
		},
		{
			name: "with_validation",
			config: &struct {
				Value string `secret:"env=TEST_VALUE,validate=nonempty"`
			}{},
			envKey:    "TEST_VALUE",
			envValue:  "test_value",
			expected:  "test_value",
			expectErr: false,
		},
		{
			name: "validation_failure",
			config: &struct {
				Value string `secret:"env=TEST_VALUE,validate=nonempty"`
			}{},
			envKey:    "TEST_VALUE",
			envValue:  "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv(tt.envKey, tt.envValue)
			defer os.Unsetenv(tt.envKey)

			err := Fetch(context.Background(), tt.config, &Options{
				Transformers: map[string]TransformFunc{
					"uppercase": func(s string) (string, error) {
						return strings.ToUpper(s), nil
					},
				},
				Validators: map[string]ValidationFunc{
					"nonempty": func(s string) error {
						if s == "" {
							return fmt.Errorf("value cannot be empty")
						}
						return nil
					},
				},
			})

			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, reflect.ValueOf(tt.config).Elem().Field(0).String())
			}
		})
	}
}

// TestSecureValue tests the secureValue type methods
func TestSecureValue(t *testing.T) {
	sv := &secureValue{}

	t.Run("set_and_get", func(t *testing.T) {
		value := "test-secret"
		sv.Set(value)
		assert.Equal(t, value, sv.Get())
	})

	t.Run("clear", func(t *testing.T) {
		value := "test-secret"
		sv.Set(value)
		sv.Clear()
		assert.Equal(t, "", sv.Get())
	})
}

// TestGetFromAWS tests the AWS secret fetching functionality
func TestGetFromAWS(t *testing.T) {
	testCases := []struct {
		name          string
		secretID      string
		mockFn        func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
		expectedValue string
		expectedError error
	}{
		{
			name:     "successful fetch",
			secretID: "test-secret",
			mockFn: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
				return &secretsmanager.GetSecretValueOutput{
					SecretString: aws.String("test-value"),
				}, nil
			},
			expectedValue: "test-value",
		},
		{
			name:     "aws error",
			secretID: "test-secret",
			mockFn: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
				return nil, fmt.Errorf("aws error")
			},
			expectedError: fmt.Errorf("failed to get value from AWS: error fetching secret test-secret: aws error"),
		},
		{
			name:     "binary secret",
			secretID: "test-secret",
			mockFn: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
				return &secretsmanager.GetSecretValueOutput{
					SecretBinary: []byte("test-value"),
				}, nil
			},
			expectedValue: "test-value",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockClient := &mockSecretsManagerClient{
				getSecretValueFn: tc.mockFn,
			}

			s := &secret{
				awsKey: tc.secretID,
			}

			cfg := aws.Config{
				Region: "us-east-1",
				Credentials: credentials.NewStaticCredentialsProvider("test", "test", "test"),
			}

			opts := &Options{
				AWS:            &cfg,
				SecretsManager: mockClient,
				cache:         make(map[string]*cachedValue),
			}

			ctx := context.WithValue(context.Background(), optionsKey, opts)
			value, err := s.Get(ctx, opts)

			if tc.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tc.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedValue, value)
			}
		})
	}
}

// TestFetchAndValidate tests the backward compatibility function
func TestFetchAndValidate(t *testing.T) {
	type Config struct {
		Value string `secret:"env=TEST_VALUE,required"`
	}

	t.Run("fetch_and_validate", func(t *testing.T) {
		os.Setenv("TEST_VALUE", "test")
		defer os.Unsetenv("TEST_VALUE")

		var cfg Config
		err := FetchAndValidate(context.Background(), &cfg)
		require.NoError(t, err)
		assert.Equal(t, "test", cfg.Value)
	})

	t.Run("validation_error", func(t *testing.T) {
		var cfg Config
		err := FetchAndValidate(context.Background(), &cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required")
	})
}

// TestCachedValue tests the cachedValue type methods
func TestCachedValue(t *testing.T) {
	t.Run("string_representation", func(t *testing.T) {
		cv := &cachedValue{
			value: "test-value",
		}
		assert.Equal(t, "test-value", cv.String())

		cv = &cachedValue{
			value: 123,
		}
		assert.Equal(t, "123", cv.String())

		cv = &cachedValue{
			secure: &secureValue{},
		}
		cv.secure.Set("secure-value")
		assert.Equal(t, "secure-value", cv.String())
	})

	t.Run("clear", func(t *testing.T) {
		cv := &cachedValue{
			value: "test-value",
		}
		cv.Clear()
		assert.Nil(t, cv.value)

		cv = &cachedValue{
			secure: &secureValue{},
		}
		cv.secure.Set("secure-value")
		cv.Clear()
		assert.Equal(t, "", cv.secure.Get())
	})
}

// TestParseTag tests the tag parsing functionality
func TestParseTag(t *testing.T) {
	type Config struct {
		Basic     string        `secret:"env=BASIC"`
		Duration  time.Duration `secret:"env=DURATION,transform=duration"`
		JSON      interface{}   `secret:"env=JSON,json"`
		YAML      interface{}   `secret:"env=YAML,yaml"`
		Transform string        `secret:"env=TRANSFORM,transform=upper"`
		AWS       string        `secret:"aws=test/secret"`
		Invalid   string        `secret:"invalid_tag"`
		Pattern   string        `secret:"env=PATTERN,pattern=[0-9]+"`
		Required  string        `secret:"env=REQUIRED,required"`
		Base64    string        `secret:"env=BASE64,base64"`
	}

	opts := &Options{
		Transformers: map[string]TransformFunc{
			"upper": func(s string) (string, error) {
				return strings.ToUpper(s), nil
			},
			"duration": func(s string) (string, error) {
				_, err := time.ParseDuration(s)
				return s, err
			},
		},
	}

	v := reflect.ValueOf(Config{})
	tests := []struct {
		name      string
		field     string
		expectErr bool
	}{
		{"basic", "Basic", false},
		{"duration", "Duration", false},
		{"json", "JSON", false},
		{"yaml", "YAML", false},
		{"transform", "Transform", false},
		{"aws", "AWS", false},
		{"invalid", "Invalid", true},
		{"pattern", "Pattern", false},
		{"required", "Required", false},
		{"base64", "Base64", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			field, _ := v.Type().FieldByName(tt.field)
			_, err := parseTag(field, opts)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestSecretGet tests the secret.Get method with various configurations
func TestSecretGet(t *testing.T) {
	tests := []struct {
		name      string
		secret    *secret
		envValue  string
		expected  string
		expectErr bool
	}{
		{
			name: "env_with_transform",
			secret: &secret{
				envKey: "TEST_ENV",
				transform: func(s string) (string, error) {
					return strings.ToUpper(s), nil
				},
			},
			envValue: "test",
			expected: "TEST",
		},
		{
			name: "env_with_validation_error",
			secret: &secret{
				envKey: "TEST_ENV",
				validation: func(s string) error {
					return fmt.Errorf("validation error")
				},
			},
			envValue:  "test",
			expectErr: true,
		},
		{
			name: "required_missing",
			secret: &secret{
				envKey:   "TEST_ENV",
				required: true,
			},
			expectErr: true,
		},
		{
			name: "with_fallback",
			secret: &secret{
				envKey:   "TEST_ENV",
				fallback: "fallback-value",
			},
			expected: "fallback-value",
		},
		{
			name: "with_pattern",
			secret: &secret{
				envKey:  "TEST_ENV",
				pattern: regexp.MustCompile(`^[0-9]+$`),
			},
			envValue: "123",
			expected: "123",
		},
		{
			name: "pattern_mismatch",
			secret: &secret{
				envKey:  "TEST_ENV",
				pattern: regexp.MustCompile(`^[0-9]+$`),
			},
			envValue:  "abc",
			expectErr: true,
		},
		{
			name: "base64_decode",
			secret: &secret{
				envKey:   "TEST_ENV",
				isBase64: true,
			},
			envValue: base64.StdEncoding.EncodeToString([]byte("test")),
			expected: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv(tt.secret.envKey, tt.envValue)
				defer os.Unsetenv(tt.secret.envKey)
			}

			value, err := tt.secret.Get(context.Background(), &Options{})
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, value)
			}
		})
	}
}

// TestGetWithCache tests the Get method with caching
func TestGetWithCache(t *testing.T) {
	s := &secret{
		envKey: "TEST_ENV",
	}

	os.Setenv("TEST_ENV", "test-value")
	defer os.Unsetenv("TEST_ENV")

	opts := &Options{
		CacheDuration: time.Hour,
		cache:         make(map[string]*cachedValue),
	}

	// First call should miss cache
	value, err := s.Get(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, "test-value", value)

	// Second call should hit cache
	value, err = s.Get(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, "test-value", value)

	// Verify the value is still accessible
	value, err = s.Get(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, "test-value", value)
}

// TestGetWithCacheExpiry tests the Get method with cache expiry
func TestGetWithCacheExpiry(t *testing.T) {
	s := &secret{
		envKey: "TEST_ENV",
	}

	os.Setenv("TEST_ENV", "test-value")
	defer os.Unsetenv("TEST_ENV")

	opts := &Options{
		CacheDuration: 1 * time.Millisecond,
		cache:         make(map[string]*cachedValue),
	}

	// First fetch should miss cache
	value, err := s.Get(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, "test-value", value)

	// Wait for cache to expire
	time.Sleep(2 * time.Millisecond)

	// Change env var
	os.Setenv("TEST_ENV", "new-value")

	// Second fetch after cache expiration should get new value
	value, err = s.Get(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, "new-value", value)
}

// TestGetWithSecureCache tests the Get method with secure caching
func TestGetWithSecureCache(t *testing.T) {
	s := &secret{
		envKey: "TEST_ENV",
	}

	os.Setenv("TEST_ENV", "test-value")
	defer os.Unsetenv("TEST_ENV")

	opts := &Options{
		CacheDuration: time.Hour,
		SecureCache:   true,
		cache:         make(map[string]*cachedValue),
	}

	// First call should miss cache
	value, err := s.Get(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, "test-value", value)

	// Second call should hit cache
	value, err = s.Get(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, "test-value", value)

	// Change env var
	os.Setenv("TEST_ENV", "new-value")

	// Third call should still return cached value
	value, err = s.Get(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, "test-value", value)
}

// TestGetWithConcurrency tests concurrent access to the Get method
func TestGetWithConcurrency(t *testing.T) {
	s := &secret{
		envKey: "TEST_ENV",
	}

	os.Setenv("TEST_ENV", "test-value")
	defer os.Unsetenv("TEST_ENV")

	opts := &Options{
		CacheDuration: time.Hour,
		cache:         make(map[string]*cachedValue),
	}

	const numGoroutines = 10
	done := make(chan bool)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				value, err := s.Get(context.Background(), opts)
				require.NoError(t, err)
				assert.Equal(t, "test-value", value)
			}
			done <- true
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestPreloadSecretsFromARNsWithMock tests preloading secrets with a mock client
func TestPreloadSecretsFromARNsWithMock(t *testing.T) {
	testCases := []struct {
		name        string
		mockFunc    func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
		arns        []string
		expectError bool
	}{
		{
			name: "successful_preload",
			mockFunc: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
				return &secretsmanager.GetSecretValueOutput{
					SecretString: aws.String("test-secret"),
				}, nil
			},
			arns: []string{"arn:aws:secretsmanager:region:account:secret:test/secret"},
		},
		{
			name: "aws_error",
			mockFunc: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
				return nil, fmt.Errorf("AWS error")
			},
			arns:        []string{"arn:aws:secretsmanager:region:account:secret:test/secret"},
			expectError: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockSecretsManagerClient{
				getSecretValueFn: tt.mockFunc,
			}

			opts := &Options{
				AWS:            aws.NewConfig(),
				SecretsManager: mockClient,
				PreloadARNs:    true,
				CacheDuration:  time.Hour,
				cache:          make(map[string]*cachedValue),
			}

			os.Setenv("SECRET_ARNS", strings.Join(tt.arns, ","))
			defer os.Unsetenv("SECRET_ARNS")

			err := preloadSecretsFromARNs(context.Background(), opts)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestGet tests the Get method with various configurations
func TestGet(t *testing.T) {
	tests := []struct {
		name        string
		secret      *secret
		mockFunc    func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
		want        string
		wantErr     bool
		errContains string
	}{
		{
			name: "successful fetch from AWS",
			secret: &secret{
				awsKey: "test-secret",
			},
			mockFunc: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
				return &secretsmanager.GetSecretValueOutput{
					SecretString: aws.String("test-value"),
				}, nil
			},
			want:    "test-value",
			wantErr: false,
		},
		// Add more test cases as needed
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockSecretsManagerClient{
				getSecretValueFn: tt.mockFunc,
			}

			cfg := aws.Config{
				Region: "us-east-1",
				Credentials: credentials.NewStaticCredentialsProvider("test", "test", "test"),
			}

			opts := &Options{
				AWS:            &cfg,
				SecretsManager: mockClient,
				cache:         make(map[string]*cachedValue),
			}

			ctx := context.WithValue(context.Background(), optionsKey, opts)
			got, err := tt.secret.Get(ctx, opts)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
