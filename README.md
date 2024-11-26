# SecretFetch

SecretFetch is a powerful and easy-to-use Go library for managing secrets in your applications. It provides a seamless way to fetch secrets from AWS Secrets Manager, environment variables, or fallback values, with built-in validation, transformation, and caching capabilities.

## Features

- AWS Secrets Manager integration (AWS SDK v2)
- Environment variable support with optional prefixing
- Fallback values for development and testing
- Native Go type support with automatic type conversion
- Simple, intuitive API using struct tags
- Safe secret handling with masking in logs
- Built-in validation with custom validators
- Pattern matching with regex support
- JSON/YAML parsing for complex configurations
- Base64 decoding support
- Configurable caching with TTL
- Value transformers for custom processing
- Concurrent access support
- Flexible configuration options

## Installation

```bash
go get github.com/crazywolf132/SecretFetch
```

## Basic Usage

```go
type Config struct {
    // Basic string value from AWS Secrets Manager or environment
    APIKey     string `secret:"aws=prod/api/key,env=API_KEY,required"`
    
    // Number with fallback value
    MaxRetries int    `secret:"env=MAX_RETRIES,fallback=3"`
    
    // Duration with pattern validation
    Timeout    time.Duration `secret:"env=TIMEOUT,fallback=30s,pattern=^[0-9]+[smh]$"`
}

// Create and populate your config
cfg := &Config{}
if err := secretfetch.Fetch(context.Background(), cfg, nil); err != nil {
    log.Fatal(err)
}
```

## Advanced Features

### Pattern Validation
```go
type Config struct {
    // Email validation
    Email    string `secret:"env=EMAIL,pattern=^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"`
    
    // IP address validation
    IPAddr   string `secret:"env=IP_ADDR,pattern=((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"`
    
    // Port number validation
    Port     string `secret:"env=PORT,pattern=^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})$"`
    
    // Version string validation
    Version  string `secret:"env=VERSION,pattern=v[0-9]+\\.[0-9]+\\.[0-9]+"`
}
```

### Custom Validation
```go
type Config struct {
    Password string `secret:"env=PASSWORD"`
}

opts := &secretfetch.Options{
    Validators: map[string]secretfetch.ValidatorFunc{
        "PASSWORD": func(value string) error {
            if len(value) < 8 {
                return fmt.Errorf("password must be at least 8 characters")
            }
            return nil
        },
    },
}
```

### Value Transformation
```go
type Config struct {
    // Transform value before use
    APIKey string `secret:"env=API_KEY"`
}

opts := &secretfetch.Options{
    Transformers: map[string]secretfetch.TransformerFunc{
        "API_KEY": func(value string) (string, error) {
            return strings.TrimSpace(value), nil
        },
    },
}
```

### Complex Configuration with JSON/YAML
```go
type DatabaseConfig struct {
    Host     string `json:"host"`
    Port     int    `json:"port"`
    Username string `json:"username"`
    Password string `json:"password"`
}

type Config struct {
    // Parse entire database config from JSON
    Database DatabaseConfig `secret:"aws=prod/db/config,json"`
    
    // Parse array from JSON
    AllowedIPs []string `secret:"env=ALLOWED_IPS,json"`
}
```

### Base64 Decoding and Binary Data
```go
type Config struct {
    // Automatically decode base64-encoded certificate
    Certificate string `secret:"env=TLS_CERT,base64"`
    
    // Store as raw bytes
    PrivateKey []byte `secret:"env=PRIVATE_KEY,base64"`
}
```

### Caching with TTL
```go
type Config struct {
    // Cache for 5 minutes
    APIKey string `secret:"aws=prod/api/key,ttl=5m"`
    
    // Cache indefinitely
    StaticConfig string `secret:"aws=prod/static/config,ttl=-1"`
}

// Global caching options
opts := &secretfetch.Options{
    DefaultTTL: 5 * time.Minute,  // Default cache duration
    Prefix: "MYAPP_",            // Prefix for all env vars
}
```

### AWS Configuration
```go
opts := &secretfetch.Options{
    AWSConfig: aws.Config{
        Region: "us-west-2",
        Credentials: credentials.NewStaticCredentialsProvider("ACCESS_KEY", "SECRET_KEY", ""),
    },
}
```

### Error Handling
```go
if err := secretfetch.Fetch(context.Background(), cfg, opts); err != nil {
    switch e := err.(type) {
    case *secretfetch.ValidationError:
        log.Printf("Validation failed: %v", e)
    case *secretfetch.PatternError:
        log.Printf("Pattern match failed: %v", e)
    case *secretfetch.RequiredError:
        log.Printf("Required value missing: %v", e)
    default:
        log.Printf("Unknown error: %v", err)
    }
}
```

## Best Practices

1. **Security**:
   - Never log sensitive values
   - Use environment variables for local development
   - Rotate secrets regularly
   - Use AWS IAM roles with minimal permissions

2. **Performance**:
   - Enable caching for frequently accessed values
   - Use appropriate TTL values based on your needs
   - Group related secrets in JSON objects to reduce AWS API calls

3. **Validation**:
   - Always validate critical configuration values
   - Use pattern matching for structured data
   - Implement custom validators for complex rules

4. **Error Handling**:
   - Check for specific error types
   - Provide clear error messages
   - Fail fast on missing required values

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
