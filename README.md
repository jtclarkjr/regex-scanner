# Regex Security Scanner

A powerful Bun TypeScript package that scans codebases for regex patterns, validates their syntax, and identifies potential security vulnerabilities including ReDoS (Regular Expression Denial of Service) attacks.

## Features

- 🔍 **JavaScript/TypeScript Focus**: Detects regex patterns in JS, TS, JSX, TSX, and Vue files
- ✅ **Validation**: Checks if regex patterns are syntactically correct
- 🛡️ **Security Analysis**: Identifies potential ReDoS vulnerabilities and other security issues
- 📊 **Multiple Output Formats**: Table, JSON, and CSV output formats
- 🎯 **Filtering Options**: Filter by severity, validity, or security issues
- 🚀 **Fast Scanning**: Built with Bun for optimal performance

## Installation

```bash
bun add github:jtclarkjr/regex-scanner
```

### Integration in Your Project

Add to your `package.json` scripts:

```json
{
  "scripts": {
    "security:regex": "regex-scan src/ --only-issues",
    "lint:regex": "regex-scan --severity critical",
    "ci:security": "regex-scan --severity high --quiet"
  }
}
```

Then run:

```bash
bun run security:regex  # Check for any security issues
bun run lint:regex      # Check for critical issues only
bun run ci:security     # Silent check for CI/CD
```

## Usage

### Basic Scanning

```bash
# Scan current directory
bun dev

# Scan specific directory
bun dev /path/to/project

# Scan specific file
bun dev /path/to/file.js
```

### Advanced Options

```bash
# Only show patterns with security issues
bun dev --only-issues

# Only show invalid patterns
bun dev --only-invalid

# Filter by severity level
bun dev --severity critical

# Change output format
bun dev --format json
bun dev --format csv

# Scan specific file extensions
bun dev --extensions "**/*.js" "**/*.ts"

# Quiet mode (suppress info messages)
bun dev --quiet
```

### Test Individual Patterns

```bash
# Test a specific regex pattern
bun dev test-pattern "(a+)+"
bun dev test-pattern "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
```

## Security Checks

The scanner detects the following security vulnerabilities:

### Critical Issues

- **Catastrophic Backtracking**: Patterns like `(a+)+` that can cause exponential time complexity
- **Nested Quantifiers**: Quantifiers inside groups that are themselves quantified

### High Severity Issues

- **Excessive Quantifiers**: High repetition counts or unbounded quantifiers that could be exploited
- **ReDoS Vulnerabilities**: General patterns vulnerable to Regular Expression Denial of Service

### Medium/Low Issues

- Various other patterns that could potentially be exploited

## Supported Patterns

The scanner detects regex patterns in JavaScript/TypeScript files:

- **Regex Literals**: `/pattern/flags`
- **RegExp Constructor**: `new RegExp('pattern')`
- **RegExp Function**: `RegExp('pattern')`
- **String Methods**: `string.match(/pattern/)`, `string.replace(/pattern/, ...)`, `string.split(/pattern/)`

## Command Line Options

| Option             | Description                                          | Default                    |
| ------------------ | ---------------------------------------------------- | -------------------------- |
| `[path]`           | Path to scan (file or directory)                     | Current directory          |
| `-e, --extensions` | File patterns to scan                                | `**/*.{js,ts,jsx,tsx,vue}` |
| `-f, --format`     | Output format (table, json, csv)                     | `table`                    |
| `--only-issues`    | Only show patterns with security issues              | `false`                    |
| `--only-invalid`   | Only show invalid regex patterns                     | `false`                    |
| `--severity`       | Minimum severity level (low, medium, high, critical) | `low`                      |
| `-q, --quiet`      | Suppress warnings and info messages                  | `false`                    |

## Exit Codes

- `0`: Success, no critical issues found
- `1`: Critical security issues detected or execution error

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

This project was created using `bun init` in bun v1.2.20. [Bun](https://bun.sh) is a fast all-in-one JavaScript runtime.
