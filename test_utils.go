package secretfetch

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// mockSecretsManagerClient is a mock implementation of the AWS Secrets Manager client
type mockSecretsManagerClient struct {
	getSecretValueFn func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

func (m *mockSecretsManagerClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if m.getSecretValueFn != nil {
		return m.getSecretValueFn(ctx, params, optFns...)
	}
	return nil, nil
}

// mockMetricsCollector implements SecurityMetricsCollector for testing
type mockMetricsCollector struct {
	metrics            []SecretAccessMetric
	onSecretAccessFunc func(metric SecretAccessMetric)
}

func (m *mockMetricsCollector) OnSecretAccess(metric SecretAccessMetric) {
	if m.onSecretAccessFunc != nil {
		m.onSecretAccessFunc(metric)
	}
	m.metrics = append(m.metrics, metric)
}
