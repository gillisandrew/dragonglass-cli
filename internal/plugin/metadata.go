// ABOUTME: Plugin metadata parsing and validation from OCI manifest annotations
// ABOUTME: Handles extraction of Obsidian plugin information and structure validation
package plugin

import (
	"fmt"
	"regexp"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Metadata represents the complete metadata for an Obsidian plugin
type Metadata struct {
	// Core plugin information from manifest.json
	ID            string `json:"id"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	MinAppVersion string `json:"minAppVersion,omitempty"`
	Description   string `json:"description,omitempty"`
	Author        string `json:"author,omitempty"`
	AuthorURL     string `json:"authorUrl,omitempty"`
	IsDesktopOnly bool   `json:"isDesktopOnly,omitempty"`
}

// ValidationError represents a plugin validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error in field '%s': %s", e.Field, e.Message)
}

// ValidationResult holds the results of plugin validation
type ValidationResult struct {
	Valid  bool
	Errors []ValidationError
	Warnings []string
}

// ManifestParser handles parsing plugin metadata from OCI manifests
type ManifestParser struct{}

// NewManifestParser creates a new manifest parser
func NewManifestParser() *ManifestParser {
	return &ManifestParser{}
}

// ParseMetadata extracts plugin metadata from OCI manifest annotations
func (p *ManifestParser) ParseMetadata(manifest *ocispec.Manifest, annotations map[string]string) (*Metadata, error) {
	if annotations == nil {
		return nil, fmt.Errorf("no annotations found in manifest")
	}

	// Extract core plugin metadata from annotations using configurable namespace
	metadata := &Metadata{}

	// Required fields - matching legacy manifest.json structure
	var ok bool
	idKey := GetAnnotationKey(AnnotationID)
	if metadata.ID, ok = annotations[idKey]; !ok {
		return nil, fmt.Errorf("required annotation '%s' not found", idKey)
	}

	nameKey := GetAnnotationKey(AnnotationName)
	if metadata.Name, ok = annotations[nameKey]; !ok {
		return nil, fmt.Errorf("required annotation '%s' not found", nameKey)
	}

	versionKey := GetAnnotationKey(AnnotationVersion)
	if metadata.Version, ok = annotations[versionKey]; !ok {
		return nil, fmt.Errorf("required annotation '%s' not found", versionKey)
	}

	// Optional fields from legacy manifest.json
	metadata.MinAppVersion = annotations[GetAnnotationKey(AnnotationMinAppVersion)]
	metadata.Description = annotations[GetAnnotationKey(AnnotationDescription)]
	metadata.Author = annotations[GetAnnotationKey(AnnotationAuthor)]
	metadata.AuthorURL = annotations[GetAnnotationKey(AnnotationAuthorURL)]

	// Parse boolean flags
	if desktopOnlyStr := annotations[GetAnnotationKey(AnnotationIsDesktopOnly)]; desktopOnlyStr == "true" {
		metadata.IsDesktopOnly = true
	}

	return metadata, nil
}

// ValidateMetadata performs comprehensive validation of plugin metadata
func (p *ManifestParser) ValidateMetadata(metadata *Metadata) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []string{},
	}

	// Validate required fields
	if metadata.ID == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "id",
			Message: "plugin ID cannot be empty",
		})
	} else if !isValidPluginID(metadata.ID) {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "id",
			Message: "plugin ID must contain only lowercase letters, numbers, and hyphens",
		})
	}

	if metadata.Name == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "name",
			Message: "plugin name cannot be empty",
		})
	}

	if metadata.Version == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "version",
			Message: "plugin version cannot be empty",
		})
	} else if !isValidVersion(metadata.Version) {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "version",
			Message: "plugin version must be valid semantic version (e.g., 1.0.0)",
		})
	}

	// Note: Repository and commit hash validation will be performed
	// during attestation verification phase, not from manifest annotations

	// Validate optional version constraints
	if metadata.MinAppVersion != "" && !isValidVersion(metadata.MinAppVersion) {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "minAppVersion",
			Message: "minimum app version must be valid semantic version",
		})
	}

	// Validate URL fields
	if metadata.AuthorURL != "" && !isValidURL(metadata.AuthorURL) {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "authorUrl",
			Message: "author URL must be a valid URL",
		})
	}

	// Note: Security attestation checks are performed separately during registry discovery
	// Provenance and SBOM attestations are queried from the registry using media types

	// Set overall validity
	result.Valid = len(result.Errors) == 0

	return result
}

// ValidatePluginStructure validates the plugin file structure from layer contents
func (p *ManifestParser) ValidatePluginStructure(layers []LayerContent) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []string{},
	}

	requiredFiles := map[string]bool{
		"main.js":     false,
		"manifest.json": false,
	}

	optionalFiles := map[string]bool{
		"styles.css": false,
		"README.md":  false,
	}

	// Check all files in all layers
	for _, layer := range layers {
		for _, file := range layer.Files {
			fileName := strings.ToLower(file.Name)

			if _, isRequired := requiredFiles[fileName]; isRequired {
				requiredFiles[fileName] = true
			}
			if _, isOptional := optionalFiles[fileName]; isOptional {
				optionalFiles[fileName] = true
			}
		}
	}

	// Validate required files are present
	for file, found := range requiredFiles {
		if !found {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "structure",
				Message: fmt.Sprintf("required file '%s' not found", file),
			})
		}
	}

	// Add warnings for missing optional files
	if !optionalFiles["styles.css"] {
		result.Warnings = append(result.Warnings, "no styles.css file found")
	}
	if !optionalFiles["README.md"] {
		result.Warnings = append(result.Warnings, "no README.md file found")
	}

	result.Valid = len(result.Errors) == 0
	return result
}

// LayerContent represents the content of an OCI layer
type LayerContent struct {
	Descriptor ocispec.Descriptor
	Files      []FileInfo
}

// FileInfo represents information about a file in a layer
type FileInfo struct {
	Name string
	Size int64
	Mode uint32
}

// Helper validation functions

func isValidPluginID(id string) bool {
	// Plugin ID should be lowercase alphanumeric with hyphens
	matched, _ := regexp.MatchString(`^[a-z0-9-]+$`, id)
	return matched && len(id) > 0 && len(id) <= 100
}

func isValidVersion(version string) bool {
	// Simple semantic version validation (major.minor.patch)
	matched, _ := regexp.MatchString(`^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$`, version)
	return matched
}

func isValidRepositoryURL(url string) bool {
	// GitHub repository URL validation
	matched, _ := regexp.MatchString(`^https://github\.com/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$`, url)
	return matched
}

func isValidCommitHash(hash string) bool {
	// SHA-1 or SHA-256 hash validation
	matched, _ := regexp.MatchString(`^[a-f0-9]{40}$|^[a-f0-9]{64}$`, hash)
	return matched
}

func isValidURL(url string) bool {
	// Basic URL validation
	return strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://")
}