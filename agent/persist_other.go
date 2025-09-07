//go:build !windows

package main

func persistWindows() string {
	return "Windows persistence is not supported on this OS."
}
