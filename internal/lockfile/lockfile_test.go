package lockfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewLockfile(t *testing.T) {
	vaultPath := "/path/to/vault"
	lockfile := NewLockfile(vaultPath)

	if lockfile.Version != LockfileVersion {
		t.Errorf("expected version %s, got %s", LockfileVersion, lockfile.Version)
	}

	if lockfile.Plugins == nil {
		t.Error("expected plugins map to be initialized")
	}

	if len(lockfile.Plugins) != 0 {
		t.Errorf("expected empty plugins map, got %d entries", len(lockfile.Plugins))
	}

	if lockfile.Metadata.VaultPath != vaultPath {
		t.Errorf("expected vault path %s, got %s", vaultPath, lockfile.Metadata.VaultPath)
	}

	if lockfile.Metadata.SchemaVersion != LockfileVersion {
		t.Errorf("expected schema version %s, got %s", LockfileVersion, lockfile.Metadata.SchemaVersion)
	}

	if err := lockfile.Validate(); err != nil {
		t.Errorf("new lockfile should be valid: %v", err)
	}
}

func TestLockfileValidation(t *testing.T) {
	tests := []struct {
		name        string
		lockfile    Lockfile
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid empty lockfile",
			lockfile:    *NewLockfile("/test"),
			expectError: false,
		},
		{
			name: "missing version",
			lockfile: Lockfile{
				Version: "",
				Plugins: make(map[string]PluginEntry),
			},
			expectError: true,
			errorMsg:    "lockfile version is required",
		},
		{
			name: "nil plugins map",
			lockfile: Lockfile{
				Version: "1",
				Plugins: nil,
			},
			expectError: true,
			errorMsg:    "plugins map cannot be nil",
		},
		{
			name: "plugin missing name",
			lockfile: Lockfile{
				Version: "1",
				Plugins: map[string]PluginEntry{
					"test": {
						Name:         "",
						OCIReference: "ghcr.io/test/plugin:v1",
						OCIDigest:    "sha256:abc123",
						InstallPath:  "/path/to/plugin",
					},
				},
			},
			expectError: true,
			errorMsg:    "name is required",
		},
		{
			name: "plugin missing OCI reference",
			lockfile: Lockfile{
				Version: "1",
				Plugins: map[string]PluginEntry{
					"test": {
						Name:         "test-plugin",
						OCIReference: "",
						OCIDigest:    "sha256:abc123",
						InstallPath:  "/path/to/plugin",
					},
				},
			},
			expectError: true,
			errorMsg:    "OCI reference is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.lockfile.Validate()
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

func TestAddPlugin(t *testing.T) {
	lockfile := NewLockfile("/test/vault")
	initialTime := lockfile.UpdatedAt

	plugin := PluginEntry{
		Name:         "test-plugin",
		Version:      "1.0.0",
		OCIReference: "ghcr.io/test/plugin:v1.0.0",
		OCIDigest:    "sha256:abc123def456",
		ImageHash:    "sha256:def456abc123",
		InstallPath:  "/vault/.obsidian/plugins/test-plugin",
		Metadata: PluginMetadata{
			Author:      "Test Author",
			Description: "A test plugin",
		},
	}

	// Wait a bit to ensure timestamp difference
	time.Sleep(10 * time.Millisecond)

	err := lockfile.AddPlugin(plugin)
	if err != nil {
		t.Fatalf("failed to add plugin: %v", err)
	}

	if len(lockfile.Plugins) != 1 {
		t.Errorf("expected 1 plugin, got %d", len(lockfile.Plugins))
	}

	if !lockfile.UpdatedAt.After(initialTime) {
		t.Error("expected UpdatedAt to be updated")
	}

	// Verify plugin was added with generated ID
	found := false
	for _, p := range lockfile.Plugins {
		if p.Name == plugin.Name && p.OCIReference == plugin.OCIReference {
			found = true
			if p.InstallTime.IsZero() {
				t.Error("expected InstallTime to be set")
			}
			if p.LastVerified.IsZero() {
				t.Error("expected LastVerified to be set")
			}
			break
		}
	}

	if !found {
		t.Error("plugin was not found in lockfile")
	}

	// Test adding plugin without name
	invalidPlugin := PluginEntry{
		OCIReference: "ghcr.io/test/invalid:v1",
	}

	err = lockfile.AddPlugin(invalidPlugin)
	if err == nil {
		t.Error("expected error when adding plugin without name")
	}
}

func TestRemovePlugin(t *testing.T) {
	lockfile := NewLockfile("/test/vault")

	plugin := PluginEntry{
		Name:         "test-plugin",
		OCIReference: "ghcr.io/test/plugin:v1.0.0",
		OCIDigest:    "sha256:abc123",
		InstallPath:  "/path/to/plugin",
	}

	err := lockfile.AddPlugin(plugin)
	if err != nil {
		t.Fatalf("failed to add plugin: %v", err)
	}

	// Get the plugin ID
	var pluginID string
	for id := range lockfile.Plugins {
		pluginID = id
		break
	}

	initialTime := lockfile.UpdatedAt
	time.Sleep(10 * time.Millisecond)

	err = lockfile.RemovePlugin(pluginID)
	if err != nil {
		t.Errorf("failed to remove plugin: %v", err)
	}

	if len(lockfile.Plugins) != 0 {
		t.Errorf("expected 0 plugins after removal, got %d", len(lockfile.Plugins))
	}

	if !lockfile.UpdatedAt.After(initialTime) {
		t.Error("expected UpdatedAt to be updated")
	}

	// Test removing non-existent plugin
	err = lockfile.RemovePlugin("non-existent")
	if err == nil {
		t.Error("expected error when removing non-existent plugin")
	}
}

func TestUpdatePluginVerification(t *testing.T) {
	lockfile := NewLockfile("/test/vault")

	plugin := PluginEntry{
		Name:         "test-plugin",
		OCIReference: "ghcr.io/test/plugin:v1.0.0",
		OCIDigest:    "sha256:abc123",
		InstallPath:  "/path/to/plugin",
	}

	err := lockfile.AddPlugin(plugin)
	if err != nil {
		t.Fatalf("failed to add plugin: %v", err)
	}

	// Get the plugin ID
	var pluginID string
	for id := range lockfile.Plugins {
		pluginID = id
		break
	}

	verification := VerificationState{
		ProvenanceVerified: true,
		SBOMVerified:      true,
		VulnScanPassed:    false,
		VerificationTime:  time.Now().UTC(),
		Warnings:          []string{"High severity vulnerability found"},
	}

	err = lockfile.UpdatePluginVerification(pluginID, verification)
	if err != nil {
		t.Errorf("failed to update plugin verification: %v", err)
	}

	updatedPlugin := lockfile.Plugins[pluginID]
	if !updatedPlugin.VerificationState.ProvenanceVerified {
		t.Error("expected provenance to be verified")
	}

	if updatedPlugin.VerificationState.VulnScanPassed {
		t.Error("expected vulnerability scan to have failed")
	}

	if len(updatedPlugin.VerificationState.Warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(updatedPlugin.VerificationState.Warnings))
	}

	// Test updating non-existent plugin
	err = lockfile.UpdatePluginVerification("non-existent", verification)
	if err == nil {
		t.Error("expected error when updating non-existent plugin")
	}
}

func TestGetAndFindPlugin(t *testing.T) {
	lockfile := NewLockfile("/test/vault")

	plugin := PluginEntry{
		Name:         "test-plugin",
		OCIReference: "ghcr.io/test/plugin:v1.0.0",
		OCIDigest:    "sha256:abc123",
		InstallPath:  "/path/to/plugin",
	}

	err := lockfile.AddPlugin(plugin)
	if err != nil {
		t.Fatalf("failed to add plugin: %v", err)
	}

	// Get plugin by ID
	var pluginID string
	for id := range lockfile.Plugins {
		pluginID = id
		break
	}

	retrievedPlugin, found := lockfile.GetPlugin(pluginID)
	if !found {
		t.Error("expected to find plugin by ID")
	}

	if retrievedPlugin.Name != plugin.Name {
		t.Errorf("expected plugin name %s, got %s", plugin.Name, retrievedPlugin.Name)
	}

	// Test getting non-existent plugin
	_, found = lockfile.GetPlugin("non-existent")
	if found {
		t.Error("expected not to find non-existent plugin")
	}

	// Find plugin by name
	foundPlugin := lockfile.FindPluginByName("test-plugin")
	if foundPlugin == nil {
		t.Error("expected to find plugin by name")
	}

	if foundPlugin.Name != plugin.Name {
		t.Errorf("expected plugin name %s, got %s", plugin.Name, foundPlugin.Name)
	}

	// Test finding non-existent plugin
	foundPlugin = lockfile.FindPluginByName("non-existent")
	if foundPlugin != nil {
		t.Error("expected not to find non-existent plugin by name")
	}
}

func TestListPlugins(t *testing.T) {
	lockfile := NewLockfile("/test/vault")

	// Test empty list
	plugins := lockfile.ListPlugins()
	if len(plugins) != 0 {
		t.Errorf("expected empty plugin list, got %d", len(plugins))
	}

	// Add some plugins
	for i := 0; i < 3; i++ {
		plugin := PluginEntry{
			Name:         fmt.Sprintf("plugin-%d", i),
			OCIReference: fmt.Sprintf("ghcr.io/test/plugin-%d:v1.0.0", i),
			OCIDigest:    fmt.Sprintf("sha256:abc%d", i),
			InstallPath:  fmt.Sprintf("/path/to/plugin-%d", i),
		}

		err := lockfile.AddPlugin(plugin)
		if err != nil {
			t.Fatalf("failed to add plugin %d: %v", i, err)
		}
	}

	plugins = lockfile.ListPlugins()
	if len(plugins) != 3 {
		t.Errorf("expected 3 plugins, got %d", len(plugins))
	}

	// Verify all plugins are present
	names := make(map[string]bool)
	for _, plugin := range plugins {
		names[plugin.Name] = true
	}

	for i := 0; i < 3; i++ {
		expectedName := fmt.Sprintf("plugin-%d", i)
		if !names[expectedName] {
			t.Errorf("expected to find plugin %s in list", expectedName)
		}
	}
}

func TestGeneratePluginID(t *testing.T) {
	name := "test-plugin"
	ociRef := "ghcr.io/test/plugin:v1.0.0"

	id1 := generatePluginID(name, ociRef)
	id2 := generatePluginID(name, ociRef)

	if id1 != id2 {
		t.Error("expected consistent plugin ID generation")
	}

	if len(id1) != 16 { // 8 bytes = 16 hex characters
		t.Errorf("expected 16-character plugin ID, got %d characters", len(id1))
	}

	// Different inputs should produce different IDs
	id3 := generatePluginID("different-plugin", ociRef)
	if id1 == id3 {
		t.Error("expected different plugin IDs for different inputs")
	}
}

func TestLoadSaveLockfile(t *testing.T) {
	tempDir := t.TempDir()
	lockfilePath := filepath.Join(tempDir, LockfileName)

	// Test loading non-existent lockfile (should return new lockfile)
	lockfile, err := LoadLockfile(lockfilePath)
	if err != nil {
		t.Fatalf("expected no error for non-existent lockfile, got: %v", err)
	}

	if lockfile.Version != LockfileVersion {
		t.Errorf("expected default lockfile version %s, got %s", LockfileVersion, lockfile.Version)
	}

	// Add a plugin
	plugin := PluginEntry{
		Name:         "test-plugin",
		Version:      "1.0.0",
		OCIReference: "ghcr.io/test/plugin:v1.0.0",
		OCIDigest:    "sha256:abc123def456",
		ImageHash:    "sha256:def456abc123",
		InstallPath:  "/vault/.obsidian/plugins/test-plugin",
		VerificationState: VerificationState{
			ProvenanceVerified: true,
			SBOMVerified:      true,
			VulnScanPassed:    true,
			VerificationTime:  time.Now().UTC(),
		},
		Metadata: PluginMetadata{
			Author:      "Test Author",
			Description: "A test plugin",
			Tags:        []string{"utility", "productivity"},
		},
	}

	err = lockfile.AddPlugin(plugin)
	if err != nil {
		t.Fatalf("failed to add plugin: %v", err)
	}

	// Save lockfile
	err = SaveLockfile(lockfile, lockfilePath)
	if err != nil {
		t.Fatalf("failed to save lockfile: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(lockfilePath); os.IsNotExist(err) {
		t.Error("lockfile was not created")
	}

	// Load and verify saved lockfile
	loadedLockfile, err := LoadLockfile(lockfilePath)
	if err != nil {
		t.Fatalf("failed to load saved lockfile: %v", err)
	}

	if len(loadedLockfile.Plugins) != 1 {
		t.Errorf("expected 1 plugin in loaded lockfile, got %d", len(loadedLockfile.Plugins))
	}

	// Verify plugin details
	found := false
	for _, p := range loadedLockfile.Plugins {
		if p.Name == plugin.Name {
			found = true
			if p.Version != plugin.Version {
				t.Errorf("expected version %s, got %s", plugin.Version, p.Version)
			}
			if !p.VerificationState.ProvenanceVerified {
				t.Error("expected provenance to be verified in loaded lockfile")
			}
			if len(p.Metadata.Tags) != 2 {
				t.Errorf("expected 2 tags, got %d", len(p.Metadata.Tags))
			}
			break
		}
	}

	if !found {
		t.Error("plugin not found in loaded lockfile")
	}

	// Test loading invalid JSON
	invalidPath := filepath.Join(tempDir, "invalid.json")
	if err := os.WriteFile(invalidPath, []byte("invalid json"), 0644); err != nil {
		t.Fatalf("failed to write invalid lockfile: %v", err)
	}

	_, err = LoadLockfile(invalidPath)
	if err == nil {
		t.Error("expected error when loading invalid JSON lockfile")
	}

	// Test saving invalid lockfile
	invalidLockfile := &Lockfile{
		Version: "", // invalid
		Plugins: make(map[string]PluginEntry),
	}

	err = SaveLockfile(invalidLockfile, lockfilePath)
	if err == nil {
		t.Error("expected error when saving invalid lockfile")
	}
}

func TestLoadFromObsidianDirectory(t *testing.T) {
	tempDir := t.TempDir()
	obsidianDir := filepath.Join(tempDir, ".obsidian")
	if err := os.MkdirAll(obsidianDir, 0755); err != nil {
		t.Fatalf("failed to create .obsidian directory: %v", err)
	}

	// Test loading from directory without lockfile
	lockfile, lockfilePath, err := LoadFromObsidianDirectory(obsidianDir)
	if err != nil {
		t.Fatalf("failed to load from obsidian directory: %v", err)
	}

	expectedPath := GetLockfilePath(obsidianDir)
	if lockfilePath != expectedPath {
		t.Errorf("expected lockfile path %s, got %s", expectedPath, lockfilePath)
	}

	if lockfile.Version != LockfileVersion {
		t.Errorf("expected version %s, got %s", LockfileVersion, lockfile.Version)
	}

	// Save lockfile and test loading existing file
	plugin := PluginEntry{
		Name:         "existing-plugin",
		OCIReference: "ghcr.io/test/existing:v1",
		OCIDigest:    "sha256:existing123",
		InstallPath:  "/path/to/existing",
	}

	err = lockfile.AddPlugin(plugin)
	if err != nil {
		t.Fatalf("failed to add plugin: %v", err)
	}

	err = SaveLockfile(lockfile, lockfilePath)
	if err != nil {
		t.Fatalf("failed to save lockfile: %v", err)
	}

	// Load again and verify existing plugin
	loadedLockfile, _, err := LoadFromObsidianDirectory(obsidianDir)
	if err != nil {
		t.Fatalf("failed to load existing lockfile: %v", err)
	}

	if len(loadedLockfile.Plugins) != 1 {
		t.Errorf("expected 1 plugin in loaded lockfile, got %d", len(loadedLockfile.Plugins))
	}

	foundPlugin := loadedLockfile.FindPluginByName("existing-plugin")
	if foundPlugin == nil {
		t.Error("expected to find existing plugin")
	}
}

func TestGetLockfilePath(t *testing.T) {
	obsidianDir := "/path/to/.obsidian"
	expected := filepath.Join(obsidianDir, LockfileName)
	result := GetLockfilePath(obsidianDir)

	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}