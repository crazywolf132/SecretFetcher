# 🔐 SecretFetch

> Your secrets deserve better than hardcoding. SecretFetch makes secret management a breeze!

[![CI](https://github.com/crazywolf132/SecretFetch/actions/workflows/ci.yml/badge.svg)](https://github.com/crazywolf132/SecretFetch/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/crazywolf132/SecretFetch)](https://goreportcard.com/report/github.com/crazywolf132/SecretFetch)
[![GoDoc](https://godoc.org/github.com/crazywolf132/SecretFetch?status.svg)](https://godoc.org/github.com/crazywolf132/SecretFetch)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🤔 The Problem

You're building a Go application and need to manage secrets. You've got a few options, but none of them are great:

1. **Hardcode them** (Please don't! 🙈)
2. **Use environment variables** (Manual management, no validation, scattered across your codebase)
3. **Use AWS Secrets Manager directly** (Complex API, no caching, lots of boilerplate)
4. **Write your own solution** (Time-consuming, error-prone, reinventing the wheel)

What if you could have:
- The simplicity of environment variables
- The security of AWS Secrets Manager
- Built-in caching and validation
- All with just a few struct tags?

That's where SecretFetch comes in! 🚀

## 🌟 Why SecretFetch?

SecretFetch gives you the best of all worlds:

- 🎯 **Dead Simple API** - Just add struct tags and go!
- 🔄 **Multi-Source Support** - AWS Secrets Manager, env vars, and fallbacks in one place
- 🚀 **Type Safety** - Automatic type conversion for strings, numbers, durations, and more
- ⚡ **Performance** - Built-in caching to reduce AWS API calls
- 🛡️ **Validation** - Pattern matching and custom validators to catch issues early
- 🔧 **Flexibility** - Transform values, decode base64, parse JSON/YAML
- 🏃‍♂️ **Zero Config** - Works out of the box with sane defaults
- 🔌 **Testability** - Mock AWS Secrets Manager for unit testing

## 🚀 Quick Start

```bash
go get github.com/crazywolf132/SecretFetch
```

```go
type Config struct {
    // Get from AWS, fallback to env var
    APIKey string `secret:"aws=prod/api/key,env=API_KEY"`
    
    // Validate email format
    Email  string `secret:"env=EMAIL,pattern=^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"`
    
    // Parse duration with fallback
    Timeout time.Duration `secret:"env=TIMEOUT,fallback=30s"`
}

cfg := &Config{}
if err := secretfetch.Fetch(context.Background(), cfg, nil); err != nil {
    log.Fatal(err)
}
```

## 🎯 Features Deep Dive

### 🔐 AWS Secrets Manager Integration

```go
// Option 1: Parse JSON secrets
type DatabaseConfig struct {
    Host     string `json:"host"`
    Username string `json:"username"`
    Password string `json:"password"`
}

type Config struct {
    // Parse entire database config from AWS Secrets Manager
    DB DatabaseConfig `secret:"aws=prod/db/config,json"`
}

// Option 2: Preload ARNs for better performance
opts := &secretfetch.Options{
    PreloadARNs: true,  // Enable ARN preloading
    AWS: &aws.Config{   // Optional: provide custom AWS config
        Region: "us-west-2",
    },
}

// Configure ARNs through environment variables
// In development:
os.Setenv("SECRET_ARNS", "arn:aws:secretsmanager:region:account:secret:name1,arn:aws:secretsmanager:region:account:secret:name2")
// or
os.Setenv("SECRET_ARN", "arn:aws:secretsmanager:region:account:secret:name")

// In production (ECS/Docker), configure in your task definition or docker-compose:
/*
  # ECS Task Definition
  {
    "containerDefinitions": [
      {
        "environment": [
          {
            "name": "SECRET_ARNS",
            "value": "arn:aws:secretsmanager:region:account:secret:name1,arn:aws:secretsmanager:region:account:secret:name2"
          }
        ]
      }
    ]
  }

  # docker-compose.yml
  services:
    app:
      environment:
        - SECRET_ARNS=arn:aws:secretsmanager:region:account:secret:name1,arn:aws:secretsmanager:region:account:secret:name2
*/
```

### 🔍 Pattern Validation

```go
type Config struct {
    // Validate IP address format
    IPAddr string `secret:"env=IP,pattern=((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"`
    
    // Validate semantic version
    Version string `secret:"env=VERSION,pattern=v[0-9]+\\.[0-9]+\\.[0-9]+"`
}
```

### 🔄 Value Transformation

```go
opts := &secretfetch.Options{
    Transformers: map[string]secretfetch.TransformFunc{
        "API_KEY": func(value string) (string, error) {
            return strings.TrimSpace(value), nil
        },
    },
}
```

### ⚡ Smart Caching

```go
opts := &secretfetch.Options{
    CacheDuration: 5 * time.Minute,  // Cache secrets for 5 minutes
}
```

### 🧪 Testing Support

SecretFetch makes testing a breeze with its mock interfaces:

```go
// Mock AWS Secrets Manager client for testing
type mockSecretsManagerClient struct {
    getSecretValueFn func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

func (m *mockSecretsManagerClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
    return m.getSecretValueFn(ctx, params, optFns...)
}

// Use in tests
opts := &secretfetch.Options{
    SecretsManager: &mockSecretsManagerClient{
        getSecretValueFn: func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
            return &secretsmanager.GetSecretValueOutput{
                SecretString: aws.String("test-secret-value"),
            }, nil
        },
    },
}
```

## Enterprise Security Features 🛡️

SecretFetch is built with enterprise-grade security in mind:

### Secure Memory Handling
```go
opts := &secretfetch.Options{
    SecureCache: true,  // Enable secure memory for caching
}
```
- Zero-copy memory handling
- Automatic memory zeroing
- Thread-safe operations
- Optional secure caching

### Audit & Compliance
```go
opts := &secretfetch.Options{
    OnSecretAccess: func(ctx context.Context, secretID string) {
        audit.Log("Secret accessed", "id", secretID)
    },
    MetricsCollector: &metrics.SecurityMetrics{
        OnSecretAccess: func(metric metrics.SecretAccessMetric) {
            prometheus.SecretAccessCounter.Inc()
        },
    },
}
```
- Detailed audit logging
- Prometheus metrics integration
- Access tracking
- Compliance reporting

### AWS Security Best Practices
- IAM role support
- VPC endpoint compatibility
- KMS integration
- CloudTrail logging

See our [SECURITY.md](SECURITY.md) for detailed security documentation and enterprise compliance information.

## 🏆 Why Better Than Alternatives?

### vs Direct AWS SDK
- 📉 **Less Code** - No more AWS boilerplate
- 🚀 **Built-in Caching** - Reduce API calls automatically
- 🎯 **Type Safety** - Automatic type conversion
- ✨ **Validation** - Catch issues before they hit production

### vs Environment Variables
- 🔐 **Multi-Source** - Use AWS for production, env vars for development
- 🛡️ **Validation** - Pattern matching and custom validators
- 🔄 **Transformation** - Process values before use
- 📦 **Structured Data** - Parse JSON/YAML automatically

### vs Other Libraries
- 🎯 **Simple API** - Just use struct tags
- 🚀 **Performance** - Smart caching built-in
- 🔧 **Flexible** - Multiple sources, validation, transformation
- 📚 **Well Documented** - Comprehensive examples and guides

## 📚 Advanced Configuration

### Options

```go
type Options struct {
    // AWS configuration
    AWS *aws.Config
    
    // Custom validation functions
    Validators map[string]ValidationFunc
    
    // Custom transformation functions
    Transformers map[string]TransformFunc
    
    // Cache duration for secrets
    CacheDuration time.Duration
    
    // Enable ARN preloading
    PreloadARNs bool
    
    // Custom Secrets Manager client for testing
    SecretsManager SecretsManagerClient
}
```

## 🤝 Contributing

Found a bug? Have a cool idea? Want to make SecretFetch even more awesome? We'd love your help! Feel free to:
- 🐛 Open an issue
- 🎉 Submit a PR
- 🌟 Give us a star
- 📚 Improve our docs

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

Made with ❤️ by [Brayden](https://github.com/crazywolf132)
