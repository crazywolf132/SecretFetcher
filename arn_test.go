package secretfetch

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSecretsManagerClient is a mock implementation of the AWS Secrets Manager client
type mockSecretsManagerClient struct {
	getSecretValueFn func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

func (m *mockSecretsManagerClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return m.getSecretValueFn(ctx, params, optFns...)
}

func TestPreloadSecretsFromARNs(t *testing.T) {
	// Setup test environment
	testCases := []struct {
		name          string
		arns          []string
		setupEnv      func()
		cleanupEnv    func()
		mockFn        func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
		expectErr     bool
		errorContains string
	}{
		{
			name: "valid_single_arn",
			arns: []string{"arn:aws:secretsmanager:us-west-2:123456789012:secret:test-secret"},
			setupEnv: func() {
				os.Setenv("SECRET_ARN", "arn:aws:secretsmanager:us-west-2:123456789012:secret:test-secret")
			},
			cleanupEnv: func() {
				os.Unsetenv("SECRET_ARN")
			},
			mockFn: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
				return &secretsmanager.GetSecretValueOutput{
					SecretString: aws.String("test-secret-value"),
				}, nil
			},
			expectErr: false,
		},
		{
			name: "multiple_valid_arns",
			arns: []string{
				"arn:aws:secretsmanager:us-west-2:123456789012:secret:test-secret-1",
				"arn:aws:secretsmanager:us-west-2:123456789012:secret:test-secret-2",
			},
			setupEnv: func() {
				os.Setenv("SECRET_ARNS", "arn:aws:secretsmanager:us-west-2:123456789012:secret:test-secret-1,arn:aws:secretsmanager:us-west-2:123456789012:secret:test-secret-2")
			},
			cleanupEnv: func() {
				os.Unsetenv("SECRET_ARNS")
			},
			mockFn: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
				return &secretsmanager.GetSecretValueOutput{
					SecretString: aws.String("test-secret-value"),
				}, nil
			},
			expectErr: false,
		},
		{
			name: "invalid_arn_format",
			arns: []string{"invalid:arn:format"},
			setupEnv: func() {
				os.Setenv("SECRET_ARN", "invalid:arn:format")
			},
			cleanupEnv: func() {
				os.Unsetenv("SECRET_ARN")
			},
			mockFn: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
				return nil, &types.ResourceNotFoundException{Message: aws.String("Secret not found")}
			},
			expectErr:     true,
			errorContains: "Secret not found",
		},
		{
			name:      "no_arns_configured",
			arns:      []string{},
			setupEnv:  func() {},
			cleanupEnv: func() {},
			mockFn: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
				return nil, &types.ResourceNotFoundException{Message: aws.String("Secret not found")}
			},
			expectErr:     true,
			errorContains: "no secret ARNs found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			tc.setupEnv()
			defer tc.cleanupEnv()

			// Create mock client
			mockClient := &mockSecretsManagerClient{
				getSecretValueFn: tc.mockFn,
			}

			// Create test options with mock client
			opts := &Options{
				PreloadARNs:    true,
				CacheDuration:  time.Minute,
				cache:          make(map[string]*cachedValue),
				AWS: &aws.Config{
					Region: "us-west-2",
				},
				SecretsManager: mockClient,
			}

			// Execute test
			err := preloadSecretsFromARNs(context.Background(), opts)

			// Verify results
			if tc.expectErr {
				require.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetSecretARNs(t *testing.T) {
	// Setup test cases
	testCases := []struct {
		name           string
		setupEnv       func()
		cleanupEnv     func()
		expectedCount  int
		expectedARNs   []string
	}{
		{
			name: "single_arn",
			setupEnv: func() {
				os.Setenv("SECRET_ARN", "arn:aws:secretsmanager:region:account:secret:name")
			},
			cleanupEnv: func() {
				os.Unsetenv("SECRET_ARN")
			},
			expectedCount: 1,
			expectedARNs: []string{"arn:aws:secretsmanager:region:account:secret:name"},
		},
		{
			name: "multiple_arns",
			setupEnv: func() {
				os.Setenv("SECRET_ARNS", "arn:aws:secretsmanager:region:account:secret:name1,arn:aws:secretsmanager:region:account:secret:name2")
			},
			cleanupEnv: func() {
				os.Unsetenv("SECRET_ARNS")
			},
			expectedCount: 2,
			expectedARNs: []string{
				"arn:aws:secretsmanager:region:account:secret:name1",
				"arn:aws:secretsmanager:region:account:secret:name2",
			},
		},
		{
			name:           "no_arns",
			setupEnv:       func() {},
			cleanupEnv:     func() {},
			expectedCount:  0,
			expectedARNs:   []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			tc.setupEnv()
			defer tc.cleanupEnv()

			// Execute test
			arns := getSecretARNs()

			// Verify results
			assert.Equal(t, tc.expectedCount, len(arns))
			assert.ElementsMatch(t, tc.expectedARNs, arns)
		})
	}
}

func TestPreloadARNsIntegration(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	// Setup test environment
	testARN := "arn:aws:secretsmanager:us-west-2:123456789012:secret:test-secret"
	os.Setenv("SECRET_ARN", testARN)
	defer os.Unsetenv("SECRET_ARN")

	// Create test options with AWS config
	opts := &Options{
		PreloadARNs:    true,
		CacheDuration:  time.Minute,
		cache:          make(map[string]*cachedValue),
	}

	// Execute test
	err := preloadSecretsFromARNs(context.Background(), opts)
	require.NoError(t, err)

	// Verify the secret was cached
	opts.cacheMu.RLock()
	defer opts.cacheMu.RUnlock()
	
	// Check if the secret exists in the cache
	cacheKey := "aws:" + testARN
	cachedSecret, exists := opts.cache[cacheKey]
	assert.True(t, exists)
	assert.NotNil(t, cachedSecret)
}
