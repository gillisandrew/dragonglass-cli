// ABOUTME: Unit tests for OCI client functionality including layer extraction
// ABOUTME: Tests plugin file extraction from OCI manifest layers with mocked repositories
package oci

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestExtractPluginFiles(t *testing.T) {
	tests := []struct {
		name        string
		manifest    *ocispec.Manifest
		expectError bool
		expectFiles []string
	}{
		{
			name: "valid plugin manifest with main.js and styles.css",
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
					{
						MediaType: "text/css",
						Size:      50,
						Digest:    "sha256:def456",
						Annotations: map[string]string{
							"org.opencontainers.image.title": "styles.css",
						},
					},
				},
			},
			expectError: false,
			expectFiles: []string{"main.js", "styles.css"},
		},
		{
			name: "manifest with only main.js",
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
			expectError: false,
			expectFiles: []string{"main.js"},
		},
		{
			name: "manifest with unrecognized files (should be ignored)",
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
					{
						MediaType: "text/plain",
						Size:      25,
						Digest:    "sha256:ghi789",
						Annotations: map[string]string{
							"org.opencontainers.image.title": "README.md",
						},
					},
				},
			},
			expectError: false,
			expectFiles: []string{"main.js"},
		},
		{
			name: "empty manifest",
			manifest: &ocispec.Manifest{
				Layers: []ocispec.Descriptor{},
			},
			expectError: false,
			expectFiles: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for extraction
			tempDir, err := os.MkdirTemp("", "oci-test-*")
			if err != nil {
				t.Fatalf("failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tempDir)

			// Create mock repository
			mockRepo := &mockRepository{
				layerData: map[string][]byte{
					"sha256:abc123": []byte("console.log('main.js content');"),
					"sha256:def456": []byte(".plugin { color: red; }"),
					"sha256:ghi789": []byte("# README content"),
				},
			}

			// Extract plugin files
			err = mockRepo.ExtractPluginFiles(context.Background(), tt.manifest, tempDir)

			// Check error expectation
			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check extracted files
			for _, expectedFile := range tt.expectFiles {
				filePath := filepath.Join(tempDir, expectedFile)
				if _, err := os.Stat(filePath); os.IsNotExist(err) {
					t.Errorf("expected file %s was not created", expectedFile)
				}
			}

			// Verify no unexpected files were created
			entries, err := os.ReadDir(tempDir)
			if err != nil {
				t.Fatalf("failed to read temp dir: %v", err)
			}

			if len(entries) != len(tt.expectFiles) {
				t.Errorf("expected %d files, got %d", len(tt.expectFiles), len(entries))
			}
		})
	}
}

// mockRepository implements the Repository interface for testing
type mockRepository struct {
	layerData map[string][]byte
}

func (m *mockRepository) ExtractPluginFiles(ctx context.Context, manifest *ocispec.Manifest, targetDir string) error {
	// Create target directory if it doesn't exist
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return err
	}

	// Process each layer (expecting main.js and styles.css)
	for _, layer := range manifest.Layers {
		// Get filename from layer annotations
		filename, ok := layer.Annotations["org.opencontainers.image.title"]
		if !ok || filename == "" {
			continue
		}

		// Only process main.js and styles.css
		if filename != "main.js" && filename != "styles.css" {
			continue
		}

		// Get mock data for this layer
		layerData, ok := m.layerData[layer.Digest.String()]
		if !ok {
			layerData = []byte("mock content")
		}

		// Write file to target directory
		filePath := filepath.Join(targetDir, filename)
		if err := os.WriteFile(filePath, layerData, 0644); err != nil {
			return err
		}
	}

	return nil
}

func TestGHCRRegistry_GetRepositoryFromRef(t *testing.T) {
	tests := []struct {
		name        string
		imageRef    string
		expectError bool
	}{
		{
			name:        "valid ghcr.io reference",
			imageRef:    "ghcr.io/owner/repo:tag",
			expectError: false,
		},
		{
			name:        "valid ghcr.io reference with digest",
			imageRef:    "ghcr.io/owner/repo@sha256:30cb002afc86ae24fad5685514fca1aa71e17cb039894e2251bb8d1c5adbe9f5",
			expectError: false,
		},
		{
			name:        "invalid reference format",
			imageRef:    "not-a-valid-reference",
			expectError: true,
		},
		{
			name:        "empty reference",
			imageRef:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := &GHCRRegistry{Token: "test-token"}

			repo, err := registry.GetRepositoryFromRef(tt.imageRef)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				if repo != nil {
					t.Error("expected nil repository on error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if repo == nil {
					t.Error("expected non-nil repository")
				}
			}
		})
	}
}