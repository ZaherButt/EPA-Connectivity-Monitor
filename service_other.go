//go:build !windows

package main

import "fmt"

func runService(cfg *Config, devMode bool) (bool, error) {
	return false, nil
}

func installService(configPath string) error {
	return fmt.Errorf("--install is only supported on Windows")
}

func uninstallService() error {
	return fmt.Errorf("--uninstall is only supported on Windows")
}
