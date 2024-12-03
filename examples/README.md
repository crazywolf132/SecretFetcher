# SecretFetch Examples

This directory contains practical examples of using SecretFetch in different scenarios.

## Basic Example
Located in `basic/main.go`, this example demonstrates:
- Loading secrets from environment variables
- Required fields
- Fallback values
- Pattern validation

## AWS Example
Located in `aws/main.go`, this example shows:
- AWS Secrets Manager integration
- JSON parsing from secrets
- Secure caching
- Preloading secrets for performance
- Mixed environment and AWS sources

## Advanced Example
Located in `advanced/main.go`, this example illustrates:
- Custom validation functions
- Value transformation
- Base64 encoded secrets
- Complex nested structures
- Pattern matching
- Type conversion

## Running the Examples

1. Set up your environment variables:
```bash
# For basic example
export API_KEY="your-api-key"
export PORT="8080"
# LOG_LEVEL will use fallback value if not set

# For AWS example
export DB_HOST="localhost" # Will use AWS fallback if not set

# For advanced example
export APP_ENV="dev"
export DEBUG="true"
export RATE_LIMIT="100"
```

2. Configure AWS credentials (for AWS and Advanced examples):
```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-west-2"
```

3. Run an example:
```bash
go run basic/main.go
# or
go run aws/main.go
# or
go run advanced/main.go
```

## Notes

- The AWS ARNs in these examples are placeholders. Replace them with your actual ARNs.
- The examples use secure caching where appropriate to protect sensitive data.
- Each example demonstrates different features of SecretFetch - choose the one that best matches your needs.
- All examples include proper error handling and logging.
