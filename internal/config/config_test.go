package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Version != "1" {
		t.Errorf("expected version '1', got '%s'", config.Version)
	}

	if config.Output.Format != "text" {
		t.Errorf("expected output format 'text', got '%s'", config.Output.Format)
	}

	if config.Registry.DefaultRegistry != "ghcr.io" {
		t.Errorf("expected default registry 'ghcr.io', got '%s'", config.Registry.DefaultRegistry)
	}

	if err := config.Validate(); err != nil {
		t.Errorf("default config should be valid: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid config",
			config:      *DefaultConfig(),
			expectError: false,
		},
		{
			name: "missing version",
			config: Config{
				Version: "",
				Output:  OutputConfig{Format: "text"},
				Registry: RegistryConfig{DefaultRegistry: "ghcr.io"},
			},
			expectError: true,
			errorMsg:    "config version is required",
		},
		{
			name: "invalid output format",
			config: Config{
				Version:  "1",
				Output:   OutputConfig{Format: "invalid"},
				Registry: RegistryConfig{DefaultRegistry: "ghcr.io"},
			},
			expectError: true,
			errorMsg:    "invalid output format",
		},
		{
			name: "missing default registry",
			config: Config{
				Version: "1",
				Output:  OutputConfig{Format: "text"},
				Registry: RegistryConfig{DefaultRegistry: ""},
			},
			expectError: true,
			errorMsg:    "default registry is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestFindObsidianDirectory(t *testing.T) {
	tempDir := t.TempDir()

	// Create nested directory structure
	deepDir := filepath.Join(tempDir, "vault", "folder", "subfolder")
	if err := os.MkdirAll(deepDir, 0755); err != nil {
		t.Fatalf("failed to create test directories: %v", err)
	}

	// Create .obsidian directory at vault level
	obsidianDir := filepath.Join(tempDir, "vault", ".obsidian")
	if err := os.MkdirAll(obsidianDir, 0755); err != nil {
		t.Fatalf("failed to create .obsidian directory: %v", err)
	}

	// Test finding from deep subdirectory
	foundDir, err := FindObsidianDirectory(deepDir)
	if err != nil {
		t.Fatalf("expected to find .obsidian directory, got error: %v", err)
	}

	if foundDir != obsidianDir {
		t.Errorf("expected to find %s, got %s", obsidianDir, foundDir)
	}

	// Test from directory without .obsidian
	noObsidianDir := filepath.Join(tempDir, "no-vault")
	if err := os.MkdirAll(noObsidianDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	_, err = FindObsidianDirectory(noObsidianDir)
	if err == nil {
		t.Errorf("expected error when no .obsidian directory found")
	}
}

func TestLoadConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, ConfigFileName)

	// Test loading non-existent config (should return default)
	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("expected no error for non-existent config, got: %v", err)
	}

	defaultConfig := DefaultConfig()
	if config.Version != defaultConfig.Version {
		t.Errorf("expected default config version %s, got %s", defaultConfig.Version, config.Version)
	}

	// Test loading valid config file
	validConfig := DefaultConfig()
	validConfig.Output.Verbose = true

	configData, err := json.MarshalIndent(validConfig, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal test config: %v", err)
	}

	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	loadedConfig, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load valid config: %v", err)
	}

	if !loadedConfig.Output.Verbose {
		t.Errorf("expected verbose=true, got verbose=false")
	}

	// Test loading invalid JSON
	invalidConfigPath := filepath.Join(tempDir, "invalid.json")
	if err := os.WriteFile(invalidConfigPath, []byte("invalid json"), 0644); err != nil {
		t.Fatalf("failed to write invalid config: %v", err)
	}

	_, err = LoadConfig(invalidConfigPath)
	if err == nil {
		t.Errorf("expected error for invalid JSON config")
	}

	// Test loading invalid config (fails validation)
	invalidConfig := Config{
		Version: "",  // invalid: empty version
		Output:  OutputConfig{Format: "text"},
		Registry: RegistryConfig{DefaultRegistry: "ghcr.io"},
	}

	invalidData, err := json.MarshalIndent(invalidConfig, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal invalid config: %v", err)
	}

	invalidValidationPath := filepath.Join(tempDir, "invalid-validation.json")
	if err := os.WriteFile(invalidValidationPath, invalidData, 0644); err != nil {
		t.Fatalf("failed to write invalid config: %v", err)
	}

	_, err = LoadConfig(invalidValidationPath)
	if err == nil {
		t.Errorf("expected validation error for config with empty version")
	}
}

func TestSaveConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, ConfigFileName)

	config := DefaultConfig()
	config.Output.Verbose = true

	// Test saving valid config
	if err := SaveConfig(config, configPath); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	// Verify file was created and is readable
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Errorf("config file was not created")
	}

	// Load and verify saved config
	loadedConfig, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load saved config: %v", err)
	}

	if !loadedConfig.Output.Verbose {
		t.Errorf("saved config doesn't match original")
	}

	// Test saving invalid config
	invalidConfig := &Config{
		Version: "", // invalid
	}

	err = SaveConfig(invalidConfig, configPath)
	if err == nil {
		t.Errorf("expected error when saving invalid config")
	}

	// Test saving to directory that doesn't exist
	deepPath := filepath.Join(tempDir, "deep", "nested", "config.json")
	if err := SaveConfig(config, deepPath); err != nil {
		t.Fatalf("failed to save config to nested directory: %v", err)
	}

	// Verify nested directory was created
	if _, err := os.Stat(filepath.Dir(deepPath)); os.IsNotExist(err) {
		t.Errorf("nested directory was not created")
	}
}

func TestLoadFromCurrentDirectory(t *testing.T) {
	// Save current working directory to restore later
	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current working directory: %v", err)
	}
	defer func() {
		os.Chdir(originalWd)
	}()

	// Create test vault structure
	tempDir := t.TempDir()
	vaultDir := filepath.Join(tempDir, "test-vault")
	obsidianDir := filepath.Join(vaultDir, ".obsidian")
	subDir := filepath.Join(vaultDir, "notes", "daily")

	if err := os.MkdirAll(obsidianDir, 0755); err != nil {
		t.Fatalf("failed to create .obsidian directory: %v", err)
	}

	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdirectory: %v", err)
	}

	// Create config file
	configPath := GetConfigPath(obsidianDir)
	testConfig := DefaultConfig()
	testConfig.Output.Color = false

	if err := SaveConfig(testConfig, configPath); err != nil {
		t.Fatalf("failed to save test config: %v", err)
	}

	// Change to subdirectory and load config
	if err := os.Chdir(subDir); err != nil {
		t.Fatalf("failed to change to test directory: %v", err)
	}

	loadedConfig, returnedConfigPath, err := LoadFromCurrentDirectory()
	if err != nil {
		t.Fatalf("failed to load config from current directory: %v", err)
	}

	if loadedConfig.Output.Color != false {
		t.Errorf("loaded config doesn't match saved config")
	}

	// Handle macOS /private/var symlink resolution
	expectedPath, _ := filepath.EvalSymlinks(configPath)
	actualPath, _ := filepath.EvalSymlinks(returnedConfigPath)
	if expectedPath != actualPath {
		t.Errorf("expected config path %s, got %s", expectedPath, actualPath)
	}

	// Test from directory without .obsidian
	noVaultDir := filepath.Join(tempDir, "no-vault")
	if err := os.MkdirAll(noVaultDir, 0755); err != nil {
		t.Fatalf("failed to create no-vault directory: %v", err)
	}

	if err := os.Chdir(noVaultDir); err != nil {
		t.Fatalf("failed to change to no-vault directory: %v", err)
	}

	_, _, err = LoadFromCurrentDirectory()
	if err == nil {
		t.Errorf("expected error when loading from directory without .obsidian")
	}
}

func TestGetConfigPath(t *testing.T) {
	obsidianDir := "/path/to/.obsidian"
	expected := filepath.Join(obsidianDir, ConfigFileName)
	result := GetConfigPath(obsidianDir)

	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}