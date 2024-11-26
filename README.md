# 🔐 SecretFetch

> Your secrets deserve better than hardcoding. SecretFetch makes secret management a breeze!

[![CI](https://github.com/crazywolf132/SecretFetch/actions/workflows/ci.yml/badge.svg)](https://github.com/crazywolf132/SecretFetch/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/crazywolf132/SecretFetch)](https://goreportcard.com/report/github.com/crazywolf132/SecretFetch)
[![GoDoc](https://godoc.org/github.com/crazywolf132/SecretFetch?status.svg)](https://godoc.org/github.com/crazywolf132/SecretFetch)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🌟 Why SecretFetch?

Managing secrets in Go applications can be a pain. AWS Secrets Manager is powerful but complex. Environment variables are simple but limited. What if you could have the best of both worlds?

SecretFetch gives you:

- 🎯 **Dead Simple API** - Just add struct tags and go!
- 🔄 **Multi-Source Support** - AWS Secrets Manager, env vars, and fallbacks in one place
- 🚀 **Type Safety** - Automatic type conversion for strings, numbers, durations, and more
- ⚡ **Performance** - Built-in caching to reduce AWS API calls
- 🛡️ **Validation** - Pattern matching and custom validators to catch issues early
- 🔧 **Flexibility** - Transform values, decode base64, parse JSON/YAML
- 🏃‍♂️ **Zero Config** - Works out of the box with sane defaults

## 🤔 The Problem

You're building a Go application and need to manage secrets. You have a few options:

1. **Hardcode them** (Please don't!)
2. **Use environment variables** (Manual management, no validation)
3. **Use AWS Secrets Manager directly** (Complex API, no caching, lots of boilerplate)
4. **Use SecretFetch** (Simple, flexible, and powerful!)

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
type DatabaseConfig struct {
    Host     string `json:"host"`
    Username string `json:"username"`
    Password string `json:"password"`
}

type Config struct {
    // Parse entire database config from AWS Secrets Manager
    DB DatabaseConfig `secret:"aws=prod/db/config,json"`
}
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
    Transformers: map[string]secretfetch.TransformerFunc{
        "API_KEY": func(value string) (string, error) {
            return strings.TrimSpace(value), nil
        },
    },
}
```

### ⚡ Smart Caching

```go
type Config struct {
    // Cache for 5 minutes
    APIKey string `secret:"aws=prod/api/key,ttl=5m"`
    
    // Cache indefinitely
    StaticConfig string `secret:"aws=prod/static/config,ttl=-1"`
}
```

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

## 🛠️ Advanced Usage

For a comprehensive technical deep-dive into all features and capabilities, check out our [Technical Documentation](TECHNICAL.md).

Additional resources in our [Wiki](https://github.com/crazywolf132/SecretFetch/wiki):

- Custom Validation Functions
- AWS Configuration Options
- Caching Strategies
- Error Handling
- Testing Strategies
- Best Practices

## 🤝 Contributing

We love contributions! Check out our [Contributing Guide](CONTRIBUTING.md) to get started.

## 📝 License

MIT © [Brayden](LICENSE)
