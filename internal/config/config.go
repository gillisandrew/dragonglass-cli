// ABOUTME: Configuration management for dragonglass CLI
// ABOUTME: Handles per-vault configuration files and user preferences
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	ConfigFileName     = "dragonglass-config.json"
	ObsidianDirName    = ".obsidian"
	DefaultConfigPerms = 0644
)

type Config struct {
	Version string `json:"version"`

	// Verification settings
	Verification VerificationConfig `json:"verification"`

	// Output preferences
	Output OutputConfig `json:"output"`

	// Registry settings
	Registry RegistryConfig `json:"registry"`
}

type VerificationConfig struct {
	StrictMode         bool `json:"strict_mode"`
	SkipVulnScan      bool `json:"skip_vuln_scan"`
	AllowHighSeverity bool `json:"allow_high_severity"`
}

type OutputConfig struct {
	Format  string `json:"format"`   // "text", "json"
	Verbose bool   `json:"verbose"`
	Color   bool   `json:"color"`
}

type RegistryConfig struct {
	DefaultRegistry string            `json:"default_registry"`
	Mirrors        map[string]string `json:"mirrors,omitempty"`
}

func DefaultConfig() *Config {
	return &Config{
		Version: "1",
		Verification: VerificationConfig{
			StrictMode:         false,
			SkipVulnScan:      false,
			AllowHighSeverity: false,
		},
		Output: OutputConfig{
			Format:  "text",
			Verbose: false,
			Color:   true,
		},
		Registry: RegistryConfig{
			DefaultRegistry: "ghcr.io",
			Mirrors:        make(map[string]string),
		},
	}
}

func (c *Config) Validate() error {
	if c.Version == "" {
		return fmt.Errorf("config version is required")
	}

	if c.Output.Format != "text" && c.Output.Format != "json" {
		return fmt.Errorf("invalid output format: %s (must be 'text' or 'json')", c.Output.Format)
	}

	if c.Registry.DefaultRegistry == "" {
		return fmt.Errorf("default registry is required")
	}

	return nil
}

func FindObsidianDirectory(startPath string) (string, error) {
	absPath, err := filepath.Abs(startPath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	currentPath := absPath
	for {
		obsidianPath := filepath.Join(currentPath, ObsidianDirName)
		if info, err := os.Stat(obsidianPath); err == nil && info.IsDir() {
			return obsidianPath, nil
		}

		parentPath := filepath.Dir(currentPath)
		if parentPath == currentPath {
			return "", fmt.Errorf("no .obsidian directory found")
		}
		currentPath = parentPath
	}
}

func GetConfigPath(obsidianDir string) string {
	return filepath.Join(obsidianDir, ConfigFileName)
}

func LoadConfig(configPath string) (*Config, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

func SaveConfig(config *Config, configPath string) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, DefaultConfigPerms); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func LoadFromCurrentDirectory() (*Config, string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get working directory: %w", err)
	}

	obsidianDir, err := FindObsidianDirectory(wd)
	if err != nil {
		return nil, "", fmt.Errorf("failed to find .obsidian directory: %w", err)
	}

	configPath := GetConfigPath(obsidianDir)
	config, err := LoadConfig(configPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load config: %w", err)
	}

	return config, configPath, nil
}