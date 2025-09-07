# Bruxo Platform Architecture

This document provides a detailed overview of the technical architecture of the Bruxo Security Platform.

## 1. Component Diagram

The system is composed of three main components that work in concert: the **Bruxo Server**, the **C2 Agent**, and the **HTML5 Frontend**.

```mermaid
graph TD
    subgraph User
        A[Operator] --> B{Bruxo CLI}
    end

    subgraph Bruxo Server (Go Backend)
        B --> C[Scan Engine]
        C --> D{Target Web App}
        C --> E[Vulnerability DB]
        C --> F[Report Generator]
        F --> G[HTML/PDF Reports]
        B --> H[C2 Server]
        H <--> I[WebSocket Hub]
    end

    subgraph External Services
        C --> J[Groq AI API]
        C --> K[CIRCL CVE API]
    end

    subgraph Target Environment
        L[C2 Agent] --> H
        L --> M[Internal Network]
    end

    subgraph Frontend
        A --> G
        G --> I
    end
```

## 2. Data Flow

1.  **Initiation**: The Operator starts a scan via the Bruxo CLI.
2.  **Scanning**: The Scan Engine dispatches concurrent requests to the Target Web App.
3.  **Analysis**: Findings are analyzed for vulnerabilities. If enabled, the engine queries external APIs (Groq for attack scenarios, CIRCL for CVEs).
4.  **C2 Operation**: The C2 Server listens for incoming agent connections. The Operator can issue commands (`internal_scan`, `persist`, etc.) via the HTML report's terminal.
5.  **Agent Execution**: The C2 Agent, deployed on a compromised host, checks in periodically, receives tasks, executes them (e.g., scans the internal network), and sends results back.
6.  **Real-time Alerts**: The WebSocket Hub pushes real-time notifications (new vulnerabilities, agent check-ins) to any connected frontend client.
7.  **Reporting**: The Report Generator compiles all collected data (scan results, CVEs, AI scenarios, C2 data) into either a technical HTML dashboard or an executive PDF report.

## 3. Technologies Used

- **Backend**: Go (Golang)
  - **HTTP Client**: `fasthttp` (for high-performance scanning).
  - **WebSockets**: `gorilla/websocket` (for real-time alerts).
  - **PDF Generation**: `chromedp` (for headless Chrome control).
- **Frontend**: HTML5, JavaScript (Vanilla), CSS.
- **AI Integration**: Groq API (Llama 3 70B Model).
- **Threat Intelligence**: CIRCL.LU CVE Search API.
- **Agent**: Go (cross-compiled for Linux & Windows).
  - **Windows Persistence**: Windows Registry (`golang.org/x/sys/windows/registry`).
  - **Linux Persistence**: systemd user services.
