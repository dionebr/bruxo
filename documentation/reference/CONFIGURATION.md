# Configuration Reference

This document details the advanced configuration options for Bruxo.

## 1. Command-Line Flags

For a complete list of runtime flags and their descriptions, please refer to the [Usage Guide](../guides/USAGE_GUIDE.md#1-command-line-parameters).

## 2. Environment Variables

Bruxo uses environment variables for sensitive data to avoid hardcoding secrets in command-line arguments.

- `GROQ_API_KEY`: **Required** for all AI-powered features. This variable holds your secret API key for the Groq service.
  - **Example**: `export GROQ_API_KEY="gsk_..."`

## 3. Configuration via File (Future)

> **Note**: This feature is on the project [Roadmap](./project/ROADMAP.md) and is not yet implemented.

A future version of Bruxo will support configuration via a YAML file (e.g., `config.yaml`). This will allow users to define complex scan profiles and settings in a reusable format.

**Example (Planned):**
```yaml
target: http://example.com
wordlist: /path/to/wordlist.txt
threads: 100

report:
  format: pdf
  type: executive
  output_file: report.pdf

ai:
  enabled: true
  provider: groq

asset:
  value: critical
```
