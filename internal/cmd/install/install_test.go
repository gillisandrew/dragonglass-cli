// ABOUTME: Unit tests for plugin installation command functionality
// ABOUTME: Tests installation workflow, directory discovery, manifest creation, and error handling
package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/gillisandrew/dragonglass-cli/internal/lockfile"
	"github.com/gillisandrew/dragonglass-cli/internal/plugin"
)

func TestFindObsidianDirectory(t *testing.T) {
	tests := []struct {
		name        string
		setupDirs   []string
		changeToDir string
		expectError bool
		expectPath  string
	}{
		{
			name:        "obsidian directory in current dir",
			setupDirs:   []string{".obsidian"},
			changeToDir: "",
			expectError: false,
			expectPath:  ".obsidian",
		},
		{
			name:        "obsidian directory in parent",
			setupDirs:   []string{".obsidian", "subdir"},
			changeToDir: "subdir",
			expectError: false,
			expectPath:  "../.obsidian",
		},
		{
			name:        "obsidian directory two levels up",
			setupDirs:   []string{".obsidian", "level1", "level1/level2"},
			changeToDir: "level1/level2",
			expectError: false,
			expectPath:  "../../.obsidian",
		},
		{
			name:        "no obsidian directory found",
			setupDirs:   []string{"somedir"},
			changeToDir: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for test
			tempDir, err := os.MkdirTemp("", "obsidian-test-*")
			if err != nil {
				t.Fatalf("failed to create temp dir: %v", err)
			}
			defer func() {
				if err := os.RemoveAll(tempDir); err != nil {
					t.Logf("failed to remove temp dir: %v", err)
				}
			}()

			// Save original working directory
			originalWd, err := os.Getwd()
			if err != nil {
				t.Fatalf("failed to get working directory: %v", err)
			}
			defer func() {
				if err := os.Chdir(originalWd); err != nil {
					t.Logf("failed to restore working directory: %v", err)
				}
			}()

			// Change to temp directory
			if err := os.Chdir(tempDir); err != nil {
				t.Fatalf("failed to change to temp dir: %v", err)
			}

			// Set up directory structure
			for _, dir := range tt.setupDirs {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatalf("failed to create dir %s: %v", dir, err)
				}
			}

			// Change to test directory if specified
			if tt.changeToDir != "" {
				if err := os.Chdir(tt.changeToDir); err != nil {
					t.Fatalf("failed to change to dir %s: %v", tt.changeToDir, err)
				}
			}

			// Test function
			result, err := findObsidianDirectory()

			// Check error expectation
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}

				// Verify the path exists and is a directory
				if _, statErr := os.Stat(result); os.IsNotExist(statErr) {
					t.Errorf("returned path does not exist: %s", result)
				}

				// Check that it contains an .obsidian directory
				expectedAbsPath, _ := filepath.Abs(result)
				if info, statErr := os.Stat(expectedAbsPath); statErr != nil || !info.IsDir() {
					t.Errorf("returned path is not a valid directory: %s", result)
				}
			}
		})
	}
}

func TestCreatePluginManifest(t *testing.T) {
	tests := []struct {
		name     string
		metadata *plugin.Metadata
		validate func(t *testing.T, manifestPath string)
	}{
		{
			name: "complete metadata",
			metadata: &plugin.Metadata{
				ID:            "test-plugin",
				Name:          "Test Plugin",
				Version:       "1.0.0",
				Description:   "Test description",
				Author:        "Test Author",
				AuthorURL:     "https://github.com/test/plugin",
				MinAppVersion: "0.15.0",
				IsDesktopOnly: true,
			},
			validate: func(t *testing.T, manifestPath string) {
				content, err := os.ReadFile(manifestPath)
				if err != nil {
					t.Fatalf("failed to read manifest: %v", err)
				}

				manifestStr := string(content)
				expectedFields := []string{
					`"id": "test-plugin"`,
					`"name": "Test Plugin"`,
					`"version": "1.0.0"`,
					`"description": "Test description"`,
					`"author": "Test Author"`,
					`"authorUrl": "https://github.com/test/plugin"`,
					`"minAppVersion": "0.15.0"`,
					`"isDesktopOnly": true`,
				}

				for _, field := range expectedFields {
					if !strings.Contains(manifestStr, field) {
						t.Errorf("manifest missing expected field: %s", field)
					}
				}
			},
		},
		{
			name: "minimal metadata",
			metadata: &plugin.Metadata{
				ID:      "minimal-plugin",
				Name:    "Minimal Plugin",
				Version: "1.0.0",
			},
			validate: func(t *testing.T, manifestPath string) {
				content, err := os.ReadFile(manifestPath)
				if err != nil {
					t.Fatalf("failed to read manifest: %v", err)
				}

				manifestStr := string(content)
				requiredFields := []string{
					`"id": "minimal-plugin"`,
					`"name": "Minimal Plugin"`,
					`"version": "1.0.0"`,
				}

				for _, field := range requiredFields {
					if !strings.Contains(manifestStr, field) {
						t.Errorf("manifest missing required field: %s", field)
					}
				}

				// Should not contain optional fields when empty
				if strings.Contains(manifestStr, `"authorUrl"`) {
					t.Error("manifest should not contain empty authorUrl field")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory
			tempDir, err := os.MkdirTemp("", "manifest-test-*")
			if err != nil {
				t.Fatalf("failed to create temp dir: %v", err)
			}
			defer func() {
				if err := os.RemoveAll(tempDir); err != nil {
					t.Logf("failed to remove temp dir: %v", err)
				}
			}()

			// Create plugin manifest
			err = createPluginManifest(tempDir, tt.metadata)
			if err != nil {
				t.Errorf("unexpected error creating manifest: %v", err)
				return
			}

			// Check manifest file was created
			manifestPath := filepath.Join(tempDir, "manifest.json")
			if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
				t.Error("manifest.json file was not created")
				return
			}

			// Run validation
			tt.validate(t, manifestPath)
		})
	}
}

func TestUpdateLockfile(t *testing.T) {
	tests := []struct {
		name        string
		setupLockfile func() (*lockfile.Lockfile, string)
		metadata    *plugin.Metadata
		imageRef    string
		digest      string
		installPath string
		expectError bool
		validate    func(t *testing.T, lockfile *lockfile.Lockfile)
	}{
		{
			name: "add plugin to empty lockfile",
			setupLockfile: func() (*lockfile.Lockfile, string) {
				tempDir, _ := os.MkdirTemp("", "lockfile-test-*")
				lockfilePath := filepath.Join(tempDir, "dragonglass-lock.json")
				lf := lockfile.NewLockfile(tempDir)
				return lf, lockfilePath
			},
			metadata: &plugin.Metadata{
				ID:          "test-plugin",
				Name:        "Test Plugin",
				Version:     "1.0.0",
				Author:      "Test Author",
				Description: "Test description",
			},
			imageRef:    "ghcr.io/test/plugin:1.0.0",
			digest:      "sha256:abc123",
			installPath: "/test/path",
			expectError: false,
			validate: func(t *testing.T, lf *lockfile.Lockfile) {
				if len(lf.Plugins) != 1 {
					t.Errorf("expected 1 plugin, got %d", len(lf.Plugins))
				}

				for _, plugin := range lf.Plugins {
					if plugin.Name != "Test Plugin" {
						t.Errorf("expected plugin name 'Test Plugin', got '%s'", plugin.Name)
					}
					if plugin.Version != "1.0.0" {
						t.Errorf("expected version '1.0.0', got '%s'", plugin.Version)
					}
					if !plugin.VerificationState.ProvenanceVerified {
						t.Error("expected provenance to be verified")
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lf, lockfilePath := tt.setupLockfile()
			defer os.RemoveAll(filepath.Dir(lockfilePath))

			err := updateLockfile(lf, lockfilePath, tt.metadata, tt.imageRef, tt.digest, tt.installPath)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}

				// Verify lockfile was saved
				if _, statErr := os.Stat(lockfilePath); os.IsNotExist(statErr) {
					t.Error("lockfile was not saved")
				}

				if tt.validate != nil {
					tt.validate(t, lf)
				}
			}
		})
	}
}

func TestExtractPluginFilesFromManifest(t *testing.T) {
	tests := []struct {
		name        string
		imageRef    string
		manifest    *ocispec.Manifest
		expectError bool
		skipAuth    bool // Skip auth-dependent tests in CI
	}{
		{
			name:     "valid manifest structure",
			imageRef: "ghcr.io/test/plugin:1.0.0",
			manifest: &ocispec.Manifest{
				Layers: []ocispec.Descriptor{
					{
						MediaType: "application/javascript",
						Size:      100,
						Digest:    "sha256:abc123",
						Annotations: map[string]string{
							"org.opencontainers.image.title": "main.js",
						},
					},
				},
			},
			expectError: true, // Will fail due to auth in test environment
			skipAuth:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipAuth {
				t.Skip("Skipping auth-dependent test in unit test environment")
			}

			tempDir, err := os.MkdirTemp("", "extract-test-*")
			if err != nil {
				t.Fatalf("failed to create temp dir: %v", err)
			}
			defer func() {
				if err := os.RemoveAll(tempDir); err != nil {
					t.Logf("failed to remove temp dir: %v", err)
				}
			}()

			err = extractPluginFilesFromManifest(context.Background(), tt.imageRef, tt.manifest, tempDir)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

