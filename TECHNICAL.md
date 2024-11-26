# SecretFetch Technical Documentation

This document provides an in-depth technical overview of all features and capabilities of the SecretFetch library.

## Table of Contents
- [Core Concepts](#core-concepts)
- [Struct Tags](#struct-tags)
- [Value Sources](#value-sources)
- [Type Conversion](#type-conversion)
- [Validation](#validation)
- [Value Processing](#value-processing)
- [Caching](#caching)
- [Error Handling](#error-handling)
- [AWS Integration](#aws-integration)
- [Concurrency](#concurrency)
- [Performance Considerations](#performance-considerations)

## Core Concepts

### The Secret Type
The internal `secret` type is the core of SecretFetch's functionality:

```go
type secret struct {
    pattern    *regexp.Regexp    // Compiled regex pattern for validation
    isBase64   bool             // Whether value should be base64 decoded
    isJSON     bool             // Whether value should be parsed as JSON
    isYAML     bool             // Whether value should be parsed as YAML
    value      string           // The actual secret value
    ttl        time.Duration    // Cache duration
    fetchedAt  time.Time        // When the value was last fetched
    validation func(string) error // Custom validation function
    transform  func(string) (string, error) // Custom transformation function
    field      reflect.StructField // The struct field this secret belongs to
    envKey     string           // Environment variable key
    fallback   string          // Fallback value
    awsKey     string          // AWS Secrets Manager key
    mu         sync.RWMutex    // Mutex for thread-safe operations
    cache      *cachedValue    // Cached value and expiration
}
```

## Struct Tags

### Available Tags
- `aws`: AWS Secrets Manager key
- `env`: Environment variable name
- `fallback`: Default value if no other source provides one
- `required`: Mark field as required
- `pattern`: Regex pattern for validation
- `base64`: Enable base64 decoding
- `json`: Parse value as JSON
- `yaml`: Parse value as YAML
- `ttl`: Cache duration

### Tag Syntax
```go
// Basic usage
`secret:"env=MY_VAR"`

// Multiple options
`secret:"aws=my/secret,env=MY_VAR,fallback=default"`

// With validation
`secret:"env=MY_VAR,pattern=^[A-Z]+$"`

// With encoding
`secret:"env=MY_VAR,base64"`

// With caching
`secret:"aws=my/secret,ttl=5m"`
```

## Value Sources

### Priority Order
1. AWS Secrets Manager (if configured and key exists)
2. Environment Variables
3. Fallback Value
4. Return error if no value found and field is required

### AWS Secrets Manager
```go
// Single value
type Config struct {
    APIKey string `secret:"aws=prod/api/key"`
}

// JSON object
type Config struct {
    Database struct {
        Host string `json:"host"`
        Port int    `json:"port"`
    } `secret:"aws=prod/db/config,json"`
}
```

### Environment Variables
```go
// Basic usage
type Config struct {
    LogLevel string `secret:"env=LOG_LEVEL"`
}

// With prefix (via Options)
opts := &secretfetch.Options{
    Prefix: "MYAPP_",  // Will look for MYAPP_LOG_LEVEL
}
```

### Fallback Values
```go
type Config struct {
    // String fallback
    Host string `secret:"env=HOST,fallback=localhost"`
    
    // Numeric fallback
    Port int `secret:"env=PORT,fallback=8080"`
    
    // Duration fallback
    Timeout time.Duration `secret:"env=TIMEOUT,fallback=30s"`
    
    // Boolean fallback
    Debug bool `secret:"env=DEBUG,fallback=false"`
}
```

## Type Conversion

### Supported Types
- `string`
- `bool`
- `int`, `int8`, `int16`, `int32`, `int64`
- `uint`, `uint8`, `uint16`, `uint32`, `uint64`
- `float32`, `float64`
- `time.Duration`
- `[]byte`
- Any struct that implements `json.Unmarshaler` or `yaml.Unmarshaler`

### Type Conversion Rules
```go
type Config struct {
    // String to int
    Port int `secret:"env=PORT,fallback=8080"`
    // "8080" -> 8080
    
    // String to bool
    Debug bool `secret:"env=DEBUG,fallback=true"`
    // "true", "1", "yes", "on" -> true
    // "false", "0", "no", "off" -> false
    
    // String to duration
    Timeout time.Duration `secret:"env=TIMEOUT,fallback=30s"`
    // "30s", "5m", "2h" -> time.Duration
    
    // Base64 to []byte
    Cert []byte `secret:"env=TLS_CERT,base64"`
    // "aGVsbG8=" -> []byte("hello")
}
```

## Validation

### Pattern Validation
```go
type Config struct {
    // Email validation
    Email string `secret:"env=EMAIL,pattern=^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"`
    
    // IP address
    IP string `secret:"env=IP,pattern=^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"`
    
    // Semantic version
    Version string `secret:"env=VERSION,pattern=^v\\d+\\.\\d+\\.\\d+$"`
    
    // UUID
    ID string `secret:"env=ID,pattern=[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"`
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
                return fmt.Errorf("too short")
            }
            if !strings.ContainsAny(value, "0123456789") {
                return fmt.Errorf("must contain a number")
            }
            return nil
        },
    },
}
```

## Value Processing

### Base64 Decoding
```go
type Config struct {
    // Decode to string
    Token string `secret:"env=TOKEN,base64"`
    
    // Decode to bytes
    Key []byte `secret:"env=KEY,base64"`
}
```

### JSON Processing
```go
type Config struct {
    // Parse object
    Database struct {
        Host string `json:"host"`
        Port int    `json:"port"`
    } `secret:"aws=db/config,json"`
    
    // Parse array
    AllowedIPs []string `secret:"env=ALLOWED_IPS,json"`
    
    // Parse complex types
    Settings map[string]interface{} `secret:"aws=app/settings,json"`
}
```

### Custom Transformers
```go
opts := &secretfetch.Options{
    Transformers: map[string]secretfetch.TransformerFunc{
        // Trim whitespace
        "USERNAME": strings.TrimSpace,
        
        // Convert to lowercase
        "EMAIL": strings.ToLower,
        
        // Custom transformation
        "API_KEY": func(v string) (string, error) {
            if !strings.HasPrefix(v, "key_") {
                v = "key_" + v
            }
            return v, nil
        },
    },
}
```

## Caching

### Cache Configuration
```go
type Config struct {
    // Cache for specific duration
    APIKey string `secret:"aws=api/key,ttl=5m"`
    
    // Cache forever
    StaticConfig string `secret:"aws=static/config,ttl=-1"`
}

// Global cache settings
opts := &secretfetch.Options{
    DefaultTTL: 10 * time.Minute,
}
```

### Cache Behavior
- Thread-safe access via mutex
- Lazy loading - only fetches when needed
- Automatic expiration
- Memory-efficient storage
- No persistence across restarts

## Error Handling

### Error Types
```go
// Validation error
type ValidationError struct {
    Field string
    Err   error
}

// Pattern match error
type PatternError struct {
    Field   string
    Pattern string
    Value   string
}

// Required field error
type RequiredError struct {
    Field string
}

// Type conversion error
type ConversionError struct {
    Field     string
    FromType  string
    ToType    string
    Value     string
}
```

### Error Handling Examples
```go
err := secretfetch.Fetch(context.Background(), cfg, opts)
switch e := err.(type) {
case *secretfetch.ValidationError:
    log.Printf("Validation failed for %s: %v", e.Field, e.Err)
case *secretfetch.PatternError:
    log.Printf("Pattern match failed for %s: %v", e.Field, e.Value)
case *secretfetch.RequiredError:
    log.Printf("Required field missing: %s", e.Field)
case *secretfetch.ConversionError:
    log.Printf("Type conversion failed for %s: %v to %v", 
        e.Field, e.FromType, e.ToType)
default:
    log.Printf("Unknown error: %v", err)
}
```

## AWS Integration

### Configuration
```go
opts := &secretfetch.Options{
    AWS: &aws.Config{
        Region: aws.String("us-west-2"),
        Credentials: credentials.NewStaticCredentialsProvider(
            "ACCESS_KEY",
            "SECRET_KEY",
            "",
        ),
    },
}
```

### Features
- Uses AWS SDK v2
- Supports IAM roles
- Automatic retry with backoff
- Cross-region access
- Supports versioned secrets
- Binary secret values

## Concurrency

### Thread Safety
- All operations are thread-safe
- Uses sync.RWMutex for cache access
- Safe for concurrent reads and writes
- No global state

### Goroutine Safety
```go
// Safe for concurrent use
for i := 0; i < 100; i++ {
    go func() {
        cfg := &Config{}
        if err := secretfetch.Fetch(context.Background(), cfg, opts); err != nil {
            log.Printf("Error: %v", err)
        }
    }()
}
```

## Performance Considerations

### Caching
- In-memory caching reduces AWS API calls
- Cache hits have near-zero overhead
- Configurable TTL per field
- Smart cache invalidation

### Memory Usage
- Only caches actively used values
- Efficient string interning
- No unnecessary allocations
- Garbage collector friendly

### AWS Optimization
- Batches AWS requests when possible
- Reuses HTTP connections
- Implements exponential backoff
- Respects AWS rate limits

### Best Practices
1. Use appropriate TTL values
2. Group related secrets in JSON
3. Use fallback values for development
4. Implement custom validators efficiently
5. Handle errors gracefully
6. Monitor AWS API usage
7. Use IAM roles with minimal permissions
8. Regularly rotate secrets
9. Implement proper logging
10. Follow security best practices
