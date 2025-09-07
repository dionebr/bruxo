# Bruxo Usage Guide

This guide covers the usage of the Bruxo CLI, from basic scans to advanced C2 operations.

## 1. Command-Line Parameters

This table provides a complete reference for all available command-line flags.

| Flag | Description |
|---|---|
| `-u` | **(Required)** Target URL for the scan. |
| `-w` | **(Required)** Path to the wordlist file. |
| `-t` | Number of concurrent threads (Default: 50). |
| `-o` | Output file for the report. |
| `-sc` | Status codes to show, comma-separated (Default: "200,204,301,302,307,403"). |
| `-fc` | Status codes to filter (not show). |
| `-x` | Extensions to append to each wordlist entry (e.g., `.php,.html`). |
| `-fx` | Extensions or keywords to ignore in paths. |
| `-rl` | Rate limit in requests per second (Default: 1000). |
| `-timeout` | Request timeout in seconds (Default: 10). |
| `-hidden` | Enables hidden content detection. |
| `-v` | Verbose mode. |
| `--attack-flow` | Enable AI-powered attack scenario generation. |
| `--report-format` | Output report format: `html` or `pdf` (Default: `html`). |
| `--report-type` | Report type: `technical` or `executive` (Default: `technical`). |
| `--asset-value` | Asset value for impact calculation: `low`, `medium`, `high`, `critical` (Default: `medium`). |
| `--enable-cve-lookup` | Enable CVE lookup for discovered technologies. |
| `--gen-phishing-campaign` | Generate an AI phishing campaign for a target persona (e.g., 'IT Admin'). |

## 2. Running Scans

### Basic Scan

```bash
./bruxo -u http://example.com -w /path/to/wordlist.txt -o report.html
```

### Advanced Scan (Executive PDF Report)

This command runs a scan, generates AI attack scenarios, performs a CVE lookup, calculates business impact based on a 'high' value asset, and outputs an executive PDF report.

```bash
./bruxo -u http://app.example.com -w common.txt -t 100 -x ".php,.bak" \
  --attack-flow \
  --enable-cve-lookup \
  --asset-value high \
  --report-format pdf \
  --report-type executive \
  -o executive_summary.pdf
```

## 3. Using the C2 Framework

Once a C2 agent is deployed and has checked in, you can interact with it via the **C2 Agents** panel in the technical HTML report.

### C2 Commands

- **Interactive Shell**: Any command not listed below is executed as a standard shell command (e.g., `whoami`, `ls -la`, `cat /etc/passwd`).
- **`persist`**: Establishes persistence on the target machine (systemd service on Linux, Registry key on Windows).
- **`upload <local_file>`**: Uploads a file from the target machine to the Bruxo server's `c2_loot/<agent_id>/` directory.
- **`download <url> <destination_path>`**: Downloads a file from a URL to the target machine.
- **`internal_scan <CIDR>`**: Instructs the agent to perform a port scan on the specified internal network range (e.g., `internal_scan 192.168.1.0/24`).

### Interactive Playbooks

In the **Attack Scenarios** panel, click on any step. The corresponding command will be automatically populated in the terminal of the relevant C2 agent, creating a one-click attack execution workflow.
