# Installation Guide

This guide provides step-by-step instructions for installing and configuring the Bruxo Security Platform from the source code.

## 1. Prerequisites

Before you begin, ensure you have the following installed on your system:

- **Go**: Version 1.18 or higher.
- **Git**: For cloning the repository.
- **Google Chrome / Chromium**: Required for the PDF report generation feature.

## 2. Installation from Source

### Step 2.1: Clone the Repository

```bash
git clone https://github.com/dionebr/bruxo.git
cd bruxo
```

### Step 2.2: Install Dependencies

Bruxo uses Go Modules to manage dependencies. Run `go mod tidy` in both the main project and agent directories to download the required packages.

```bash
# Install server dependencies
go mod tidy

# Install agent dependencies
cd agent
go mod tidy
cd ..
```

## 3. Build & Compilation

### Step 3.1: Compile the Bruxo Server

From the root directory of the project, run the build command:

```bash
# This will create the 'bruxo' executable in the current directory
go build -o bruxo bruxo.go
```

### Step 3.2: Cross-Compile the C2 Agent

The agent is designed to be cross-compiled for different target operating systems.

- **To compile for Linux (64-bit):**
  ```bash
  cd agent
  GOOS=linux GOARCH=amd64 go build -o agent_linux
  cd ..
  ```

- **To compile for Windows (64-bit):**
  ```bash
  cd agent
  GOOS=windows GOARCH=amd64 go build -o agent_windows.exe
  cd ..
  ```

## 4. Environment Configuration

To enable AI-powered features, you must configure your Groq API key. Bruxo reads this key from an environment variable.

```bash
# Replace with your actual API key
export GROQ_API_KEY="gsk_YourSecretKeyHere"
```

> **Note**: You can add this line to your shell profile (`.bashrc`, `.zshrc`, etc.) to make the setting permanent.

After completing these steps, Bruxo is ready to use. Refer to the [Usage Guide](../guides/USAGE_GUIDE.md) for instructions on how to run a scan.
