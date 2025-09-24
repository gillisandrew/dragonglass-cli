package plugin

import (
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestManifestParser_ParseMetadata_New(t *testing.T) {
	parser := NewManifestParser(nil)

	tests := []struct {
		name        string
		annotations map[string]string
		wantError   bool
		validate    func(*testing.T, *Metadata)
	}{
		{
			name: "complete valid metadata",
			annotations: map[string]string{
				GetAnnotationKey(AnnotationID):            "test-plugin",
				GetAnnotationKey(AnnotationName):          "Test Plugin",
				GetAnnotationKey(AnnotationVersion):       "1.0.0",
				GetAnnotationKey(AnnotationDescription):   "A test plugin",
				GetAnnotationKey(AnnotationAuthor):        "Test Author",
				GetAnnotationKey(AnnotationMinAppVersion): "0.15.0",
				GetAnnotationKey(AnnotationIsDesktopOnly): "true",
			},
			wantError: false,
			validate: func(t *testing.T, m *Metadata) {
				if m.ID != "test-plugin" {
					t.Errorf("expected ID 'test-plugin', got %s", m.ID)
				}
				if m.Name != "Test Plugin" {
					t.Errorf("expected name 'Test Plugin', got %s", m.Name)
				}
				if m.Version != "1.0.0" {
					t.Errorf("expected version '1.0.0', got %s", m.Version)
				}
				if !m.IsDesktopOnly {
					t.Error("expected IsDesktopOnly to be true")
				}
			},
		},
		{
			name: "minimal required fields",
			annotations: map[string]string{
				GetAnnotationKey(AnnotationID):      "minimal-plugin",
				GetAnnotationKey(AnnotationName):    "Minimal Plugin",
				GetAnnotationKey(AnnotationVersion): "0.1.0",
			},
			wantError: false,
			validate: func(t *testing.T, m *Metadata) {
				if m.ID != "minimal-plugin" {
					t.Errorf("expected ID 'minimal-plugin', got %s", m.ID)
				}
				if m.IsDesktopOnly {
					t.Error("expected IsDesktopOnly to be false by default")
				}
			},
		},
		{
			name:        "missing annotations",
			annotations: nil,
			wantError:   true,
		},
		{
			name: "missing required field",
			annotations: map[string]string{
				GetAnnotationKey(AnnotationName):    "Test Plugin",
				GetAnnotationKey(AnnotationVersion): "1.0.0",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := &ocispec.Manifest{
				MediaType: ocispec.MediaTypeImageManifest,
			}

			metadata, err := parser.ParseMetadata(manifest, tt.annotations)

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

			if metadata == nil {
				t.Error("expected metadata but got nil")
				return
			}

			if tt.validate != nil {
				tt.validate(t, metadata)
			}
		})
	}
}

func TestManifestParser_ValidateMetadata_New(t *testing.T) {
	parser := NewManifestParser(nil)

	tests := []struct {
		name       string
		metadata   *Metadata
		wantValid  bool
		wantErrors int
	}{
		{
			name: "valid metadata",
			metadata: &Metadata{
				ID:      "valid-plugin",
				Name:    "Valid Plugin",
				Version: "1.0.0",
			},
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "missing required fields",
			metadata: &Metadata{
				Name: "Test Plugin",
			},
			wantValid:  false,
			wantErrors: 2, // missing id, version
		},
		{
			name: "invalid plugin ID",
			metadata: &Metadata{
				ID:      "Invalid_Plugin_ID",
				Name:    "Test Plugin",
				Version: "1.0.0",
			},
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name: "invalid version",
			metadata: &Metadata{
				ID:      "test-plugin",
				Name:    "Test Plugin",
				Version: "invalid-version",
			},
			wantValid:  false,
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.ValidateMetadata(tt.metadata)

			if result.Valid != tt.wantValid {
				t.Errorf("expected valid=%v, got %v", tt.wantValid, result.Valid)
			}

			if len(result.Errors) != tt.wantErrors {
				t.Errorf("expected %d errors, got %d: %v", tt.wantErrors, len(result.Errors), result.Errors)
			}
		})
	}
}
