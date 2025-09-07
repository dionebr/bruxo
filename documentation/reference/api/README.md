# API Documentation

Bruxo exposes a set of internal HTTP endpoints that are used by the C2 agent and the frontend dashboard. This document provides a reference for those endpoints.

> **Note**: These APIs are primarily for internal use and may change in future versions.

## C2 Agent API (Listens on `:8080`)

### `POST /c2/checkin`
- **Purpose**: Allows a new C2 agent to register with the server.
- **Request Body**:
  ```json
  {"hostname": "target-machine", "os": "linux"}
  ```
- **Response Body**:
  ```json
  {"id": "agent-1662588741"}
  ```

### `GET /c2/tasks/{agent_id}`
- **Purpose**: Long-polls for a new task from the agent's queue.
- **Response Body** (if task exists):
  ```json
  {"id": "task-123", "command": "whoami"}
  ```

### `POST /c2/results/{agent_id}`
- **Purpose**: Submits the output of an executed task.
- **Request Body**:
  ```json
  {"task_id": "task-123", "result": "root"}
  ```

### `POST /c2/upload/{agent_id}`
- **Purpose**: Uploads a file from the agent to the server.
- **Request Body**: Raw binary data of the file.

## Frontend API

### `GET /api/agents`
- **Purpose**: Returns a JSON object of all registered C2 agents.

### `POST /api/agents/{agent_id}/tasks`
- **Purpose**: Enqueues a new command for a specific agent.
- **Request Body**:
  ```json
  {"command": "ls -la"}
  ```

### `GET /api/tasks/{task_id}`
- **Purpose**: Polls for the result of a specific task.
- **Response Body**:
  ```json
  {"id": "task-123", "command": "ls -la", "result": "total 4...", "status": "completed"}
  ```

### `GET /ws`
- **Purpose**: Upgrades the HTTP connection to a WebSocket for real-time alerts.
