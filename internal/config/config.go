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

// ConfigOpts configures how configuration is loaded and managed
type ConfigOpts struct {
	// Override config file path (default: auto-discover)
	ConfigPath string

	// Whether to create default config if none exists
	CreateIfMissing bool

	// Override working directory for auto-discovery
	WorkingDir string
}

// DefaultConfigOpts returns default configuration loading options
func DefaultConfigOpts() *ConfigOpts {
	return &ConfigOpts{
		CreateIfMissing: true,
	}
}

// WithConfigPath sets a custom config file path
func (opts *ConfigOpts) WithConfigPath(path string) *ConfigOpts {
	opts.ConfigPath = path
	return opts
}

// WithWorkingDir sets a custom working directory for auto-discovery
func (opts *ConfigOpts) WithWorkingDir(dir string) *ConfigOpts {
	opts.WorkingDir = dir
	return opts
}

// WithCreateIfMissing controls whether to create default config when missing
func (opts *ConfigOpts) WithCreateIfMissing(create bool) *ConfigOpts {
	opts.CreateIfMissing = create
	return opts
}

// ConfigManager handles configuration loading and management
type ConfigManager struct {
	opts *ConfigOpts
}

// NewConfigManager creates a configuration manager with the given options
func NewConfigManager(opts *ConfigOpts) *ConfigManager {
	if opts == nil {
		opts = DefaultConfigOpts()
	}
	return &ConfigManager{opts: opts}
}

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

// LoadConfig loads configuration using the configured options
func (cm *ConfigManager) LoadConfig() (*Config, string, error) {
	// Use explicit path if provided
	if cm.opts.ConfigPath != "" {
		config, err := LoadConfig(cm.opts.ConfigPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, "", fmt.Errorf("failed to load config from %s: %w", cm.opts.ConfigPath, err)
		}
		if err == nil {
			return config, cm.opts.ConfigPath, nil
		}
		if !cm.opts.CreateIfMissing {
			return nil, "", fmt.Errorf("config file not found: %s", cm.opts.ConfigPath)
		}
		// Create default config at the specified path
		defaultConfig := DefaultConfig()
		if err := SaveConfig(defaultConfig, cm.opts.ConfigPath); err != nil {
			return nil, "", fmt.Errorf("failed to create default config: %w", err)
		}
		return defaultConfig, cm.opts.ConfigPath, nil
	}

	// Auto-discover from working directory
	wd := cm.opts.WorkingDir
	if wd == "" {
		var err error
		wd, err = os.Getwd()
		if err != nil {
			return nil, "", fmt.Errorf("failed to get working directory: %w", err)
		}
	}

	obsidianDir, err := FindObsidianDirectory(wd)
	if err != nil {
		return nil, "", fmt.Errorf("failed to find .obsidian directory: %w", err)
	}

	configPath := GetConfigPath(obsidianDir)
	config, err := LoadConfig(configPath)
	if err != nil {
		if !os.IsNotExist(err) || !cm.opts.CreateIfMissing {
			return nil, "", fmt.Errorf("failed to load config: %w", err)
		}
		// Create default config in discovered obsidian directory
		defaultConfig := DefaultConfig()
		if err := SaveConfig(defaultConfig, configPath); err != nil {
			return nil, "", fmt.Errorf("failed to create default config: %w", err)
		}
		return defaultConfig, configPath, nil
	}

	return config, configPath, nil
}

// Legacy function for backward compatibility
func LoadFromCurrentDirectory() (*Config, string, error) {
	manager := NewConfigManager(DefaultConfigOpts())
	return manager.LoadConfig()
}