# Troubleshooting Guide

This guide covers common issues and their solutions.

### 1. PDF Generation Fails

- **Symptom**: Running a scan with `--report-format pdf` fails with an error related to `chromedp` or `context deadline exceeded`.
- **Cause**: The PDF generation feature relies on a headless instance of Google Chrome or Chromium. It must be installed on the machine running Bruxo.
- **Solution**: Install Google Chrome or Chromium. On a headless Linux server, you can install it via `sudo apt-get install -y chromium-browser`.

### 2. C2 Agent Does Not Check In

- **Symptom**: The agent runs on the target, but does not appear in the C2 panel.
- **Cause 1**: Network connectivity. The target machine cannot reach the Bruxo server on port `:8080`.
- **Solution 1**: Check firewalls, network ACLs, and ensure the Bruxo server's IP is reachable from the target.
- **Cause 2**: Incorrect server address. The `c2Server` variable in `agent/main.go` is hardcoded to `http://localhost:8080`. This only works if the agent is run on the same machine as the server.
- **Solution 2**: Before compiling the agent, edit the `c2Server` variable in `agent/main.go` to point to the public/reachable IP address of your Bruxo server.

### 3. Build Fails on Linux with 'windows/registry' Error

- **Symptom**: `go build` fails on a non-Windows machine with an error about `golang.org/x/sys/windows/registry`.
- **Cause**: The Go toolchain is attempting to compile Windows-specific code.
- **Solution**: This was resolved by implementing build tags. If you encounter this, ensure your Go version is 1.18+ and that the files `persist_windows.go` and `persist_other.go` exist in the `agent` directory with the correct `//go:build` tags at the top.
