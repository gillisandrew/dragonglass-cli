package plugin

import (
	"strings"
	"testing"
)

func TestAnnotationPrefix(t *testing.T) {
	// Test default annotation prefix
	expectedDefault := "vnd.obsidian.plugin"
	if AnnotationPrefix != expectedDefault {
		t.Logf("AnnotationPrefix is set to: %s (expected default: %s)", AnnotationPrefix, expectedDefault)
		// Don't fail - this could be set via linker flags
	}

	// Test GetAnnotationKey function
	key := GetAnnotationKey("test")
	expected := AnnotationPrefix + ".test"
	if key != expected {
		t.Errorf("GetAnnotationKey('test') = %s; expected %s", key, expected)
	}
}

func TestAnnotationConstants(t *testing.T) {
	constants := []string{
		AnnotationID,
		AnnotationName,
		AnnotationVersion,
		AnnotationMinAppVersion,
		AnnotationDescription,
		AnnotationAuthor,
		AnnotationAuthorURL,
		AnnotationIsDesktopOnly,
	}

	for _, constant := range constants {
		if constant == "" {
			t.Error("annotation constant is empty")
		}

		fullKey := GetAnnotationKey(constant)
		if !strings.HasPrefix(fullKey, AnnotationPrefix) {
			t.Errorf("annotation key %s does not have correct prefix %s", fullKey, AnnotationPrefix)
		}
	}
}

func TestGetAnnotationKey(t *testing.T) {
	tests := []struct {
		field    string
		expected string
	}{
		{"id", AnnotationPrefix + ".id"},
		{"name", AnnotationPrefix + ".name"},
		{"version", AnnotationPrefix + ".version"},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			result := GetAnnotationKey(tt.field)
			if result != tt.expected {
				t.Errorf("GetAnnotationKey(%s) = %s; expected %s", tt.field, result, tt.expected)
			}
		})
	}
}