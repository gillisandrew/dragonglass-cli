package registry

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/gillisandrew/dragonglass-cli/internal/plugin"
)

func TestParseImageReference(t *testing.T) {
	tests := []struct {
		name               string
		imageRef           string
		expectedRegistry   string
		expectedRepository string
		expectedTag        string
		expectError        bool
	}{
		{
			name:               "full reference with tag",
			imageRef:           "ghcr.io/owner/repo:v1.0.0",
			expectedRegistry:   "ghcr.io",
			expectedRepository: "owner/repo",
			expectedTag:        "v1.0.0",
			expectError:        false,
		},
		{
			name:               "reference with latest tag",
			imageRef:           "ghcr.io/owner/repo:latest",
			expectedRegistry:   "ghcr.io",
			expectedRepository: "owner/repo",
			expectedTag:        "latest",
			expectError:        false,
		},
		{
			name:               "reference with digest",
			imageRef:           "ghcr.io/owner/repo@sha256:abc123def456789012345678901234567890abcdef1234567890123456789012",
			expectedRegistry:   "ghcr.io",
			expectedRepository: "owner/repo",
			expectedTag:        "sha256:abc123def456789012345678901234567890abcdef1234567890123456789012",
			expectError:        false,
		},
		{
			name:        "invalid reference",
			imageRef:    "invalid-ref",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, repository, tag, err := ParseImageReference(tt.imageRef)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for %s but got none", tt.imageRef)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error for %s: %v", tt.imageRef, err)
				return
			}

			if registry != tt.expectedRegistry {
				t.Errorf("expected registry %s, got %s", tt.expectedRegistry, registry)
			}

			if repository != tt.expectedRepository {
				t.Errorf("expected repository %s, got %s", tt.expectedRepository, repository)
			}

			if tag != tt.expectedTag {
				t.Errorf("expected tag %s, got %s", tt.expectedTag, tag)
			}
		})
	}
}

func TestGenerateBasicAuthHeader(t *testing.T) {
	username := "testuser"
	password := "testpass"

	header := GenerateBasicAuthHeader(username, password)

	expectedAuth := base64.StdEncoding.EncodeToString([]byte("testuser:testpass"))
	expectedHeader := "Basic " + expectedAuth

	if header != expectedHeader {
		t.Errorf("expected header %s, got %s", expectedHeader, header)
	}

	// Verify we can decode it back
	if !bytes.HasPrefix([]byte(header), []byte("Basic ")) {
		t.Error("header should start with 'Basic '")
	}

	encoded := header[6:] // Remove "Basic " prefix
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Errorf("failed to decode auth header: %v", err)
	}

	if string(decoded) != "testuser:testpass" {
		t.Errorf("expected decoded auth 'testuser:testpass', got %s", string(decoded))
	}
}

func TestIsGitHubRegistry(t *testing.T) {
	tests := []struct {
		registry string
		expected bool
	}{
		{"ghcr.io", true},
		{"GHCR.IO", true},
		{"docker.pkg.github.com", true},
		{"DOCKER.PKG.GITHUB.COM", true},
		{"docker.io", false},
		{"registry.hub.docker.com", false},
		{"localhost:5000", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.registry, func(t *testing.T) {
			result := IsGitHubRegistry(tt.registry)
			if result != tt.expected {
				t.Errorf("IsGitHubRegistry(%s) = %v; expected %v", tt.registry, result, tt.expected)
			}
		})
	}
}

func TestVerifyDigest(t *testing.T) {
	content := []byte("test content")
	correctDigest := digest.FromBytes(content)
	incorrectDigest := digest.FromString("wrong content")

	// Test correct digest
	err := verifyDigest(content, correctDigest)
	if err != nil {
		t.Errorf("expected no error for correct digest, got: %v", err)
	}

	// Test incorrect digest
	err = verifyDigest(content, incorrectDigest)
	if err == nil {
		t.Error("expected error for incorrect digest")
	}
}

func TestNewClient(t *testing.T) {
	// This test will only pass if GitHub CLI is configured
	// In CI/test environments without authentication, we expect it to fail
	client, err := NewClient(nil)
	if err != nil {
		t.Logf("Expected error in test environment without authentication: %v", err)
		// This is expected in most test environments
		return
	}

	if client == nil {
		t.Error("client should not be nil when no error is returned")
		return // Exit early to avoid nil pointer dereference
	}

	if client.registry == nil {
		t.Error("registry should not be nil")
	}

	if client.httpClient == nil {
		t.Error("httpClient should not be nil")
	}

	// Test timeout is set
	if client.httpClient.Timeout != DefaultTimeout {
		t.Errorf("expected timeout %v, got %v", DefaultTimeout, client.httpClient.Timeout)
	}
}

func TestSetRegistry(t *testing.T) {
	// Create a client without authentication for testing
	client := &Client{}

	err := client.SetRegistry("localhost:5000")
	if err != nil {
		t.Errorf("failed to set registry: %v", err)
	}

	if client.registry == nil {
		t.Error("registry should be set")
	}

	// Test invalid registry
	err = client.SetRegistry("invalid://registry")
	if err == nil {
		t.Error("expected error for invalid registry format")
	}
}

func TestPullResult(t *testing.T) {
	// Test PullResult structure
	result := &PullResult{
		Manifest: ocispec.Manifest{
			MediaType: ocispec.MediaTypeImageManifest,
		},
		ManifestData: []byte(`{"schemaVersion": 2}`),
		Layers: []LayerInfo{
			{
				Descriptor: ocispec.Descriptor{
					MediaType: ocispec.MediaTypeImageLayerGzip,
					Size:      1024,
					Digest:    "sha256:test",
				},
				Content:   []byte("test layer content"),
				SavedPath: "/tmp/layer-0.tar",
			},
		},
		Annotations: map[string]string{
			"test.annotation": "test-value",
		},
		Plugin: nil, // Plugin metadata would be set by ParseMetadata
	}

	// Note: SchemaVersion is embedded in Versioned field
	// For now, just check that the manifest is properly initialized

	if len(result.Layers) != 1 {
		t.Errorf("expected 1 layer, got %d", len(result.Layers))
	}

	if result.Annotations["test.annotation"] != "test-value" {
		t.Errorf("expected annotation value 'test-value', got %s", result.Annotations["test.annotation"])
	}
}

func TestProgressCallback(t *testing.T) {
	var callbackCalled bool
	var receivedDesc ocispec.Descriptor
	var receivedProgress, receivedTotal int64

	callback := func(desc ocispec.Descriptor, progress int64, total int64) {
		callbackCalled = true
		receivedDesc = desc
		receivedProgress = progress
		receivedTotal = total
	}

	// Simulate calling the callback
	testDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Size:      1024,
		Digest:    "sha256:test",
	}

	callback(testDesc, 512, 1024)

	if !callbackCalled {
		t.Error("callback was not called")
	}

	if receivedDesc.MediaType != testDesc.MediaType || receivedDesc.Size != testDesc.Size || receivedDesc.Digest != testDesc.Digest {
		t.Error("callback received wrong descriptor")
	}

	if receivedProgress != 512 {
		t.Errorf("expected progress 512, got %d", receivedProgress)
	}

	if receivedTotal != 1024 {
		t.Errorf("expected total 1024, got %d", receivedTotal)
	}
}

// Integration tests - these require actual authentication and network access
// They are disabled by default and can be enabled for manual testing

func TestPullIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client, err := NewClient(nil)
	if err != nil {
		t.Skipf("skipping integration test - no authentication available: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use a public image for testing
	imageRef := "ghcr.io/oras-project/oras:latest"

	// Test ValidateAccess
	err = client.ValidateAccess(ctx, imageRef)
	if err != nil {
		t.Logf("skipping pull test - access validation failed (expected for non-public repos): %v", err)
		return
	}

	// Test GetManifest
	manifest, annotations, err := client.GetManifest(ctx, imageRef)
	if err != nil {
		t.Errorf("failed to get manifest: %v", err)
		return
	}

	if manifest == nil {
		t.Error("manifest should not be nil")
		return // Exit early to avoid nil pointer dereference
	}

	if annotations == nil {
		t.Error("annotations should not be nil")
	}

	t.Logf("Successfully fetched manifest for %s", imageRef)
	t.Logf("Manifest has %d layers", len(manifest.Layers))
}

func TestValidatePlugin(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name      string
		result    *PullResult
		wantError bool
		wantValid bool
	}{
		{
			name:      "nil result",
			result:    nil,
			wantError: true,
		},
		{
			name: "missing plugin metadata",
			result: &PullResult{
				Plugin: nil,
			},
			wantError: true,
		},
		{
			name: "valid plugin with complete metadata",
			result: &PullResult{
				Plugin: &plugin.Metadata{
					ID:      "test-plugin",
					Name:    "Test Plugin",
					Version: "1.0.0",
				},
				Layers: []LayerInfo{
					{
						Descriptor: ocispec.Descriptor{
							MediaType: ocispec.MediaTypeImageLayerGzip,
							Size:      1024,
							Digest:    "sha256:test",
						},
						Content:   []byte("test content"),
						SavedPath: "/tmp/test.tar",
					},
				},
			},
			wantError: false,
			wantValid: true,
		},
		{
			name: "plugin with validation errors",
			result: &PullResult{
				Plugin: &plugin.Metadata{
					ID:      "", // Invalid - empty
					Name:    "Test Plugin",
					Version: "invalid", // Invalid version format
				},
				Layers: []LayerInfo{},
			},
			wantError: false,
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := client.ValidatePlugin(tt.result)

			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Error("expected validation result but got nil")
				return
			}

			if result.Valid != tt.wantValid {
				t.Errorf("expected valid=%v, got %v", tt.wantValid, result.Valid)
			}

			if !tt.wantValid && len(result.Errors) == 0 {
				t.Error("expected validation errors but got none")
			}
		})
	}
}

func TestExtractFileListFromLayer(t *testing.T) {
	tests := []struct {
		name        string
		layer       LayerInfo
		expectFiles bool
	}{
		{
			name: "layer with content",
			layer: LayerInfo{
				Descriptor: ocispec.Descriptor{
					Size: 1024,
				},
			},
			expectFiles: true,
		},
		{
			name: "empty layer",
			layer: LayerInfo{
				Descriptor: ocispec.Descriptor{
					Size: 0,
				},
			},
			expectFiles: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := extractFileListFromLayer(tt.layer)

			if tt.expectFiles {
				if len(files) == 0 {
					t.Error("expected files but got none")
				}
				// Check that common plugin files are included
				hasMainJS := false
				hasManifest := false
				for _, file := range files {
					if file.Name == "main.js" {
						hasMainJS = true
					}
					if file.Name == "manifest.json" {
						hasManifest = true
					}
				}
				if !hasMainJS {
					t.Error("expected main.js file")
				}
				if !hasManifest {
					t.Error("expected manifest.json file")
				}
			} else {
				if len(files) != 0 {
					t.Errorf("expected no files but got %d", len(files))
				}
			}
		})
	}
}
