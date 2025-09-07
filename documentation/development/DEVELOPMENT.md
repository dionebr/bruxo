# Developer Guide

This guide is for developers who want to contribute to the Bruxo project.

## 1. Codebase Structure

- `bruxo.go`: The main entry point and core logic for the server, scanner, and C2 hub.
- `report_template.html`: HTML template for the technical dashboard.
- `executive_template.html`: HTML template for the executive PDF report.
- `agent/`: Directory containing the C2 agent source code.
  - `main.go`: Core agent logic for check-in, tasking, and command execution.
  - `persist_windows.go`: Windows-specific persistence logic (using build tags).
  - `persist_other.go`: Placeholder persistence logic for non-Windows OSes.
- `go.mod` / `go.sum`: Go module files for managing dependencies.

## 2. Contribution Guidelines

1.  **Fork the repository** on GitHub.
2.  **Create a new branch** for your feature or bug fix: `git checkout -b feat/my-new-feature`.
3.  **Write clean, commented code** that follows Go conventions.
4.  **Update documentation** if you add or change a feature.
5.  **Submit a Pull Request** to the `main` branch of the original repository.

## 3. Adding a New Vulnerability Check

To add a new check, modify the `vulnerabilityChecks` slice in `bruxo.go`. Each check requires:

- `Name`: A unique name for the vulnerability.
- `Severity`: `Critical`, `High`, `Medium`, or `Low`.
- `Check`: A function that takes the URL and response body and returns `true` if the vulnerability is present.
- `Description` & `Recommendation`: Text to be displayed in the report.

## 4. Cross-Platform Development

The C2 agent uses Go build tags to handle platform-specific code. When adding features like persistence, create separate files for each OS (e.g., `_windows.go`, `_linux.go`) and use the `//go:build` directive at the top of the file.
