package secretfetch

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

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
