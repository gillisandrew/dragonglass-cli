// ABOUTME: Plugin metadata configuration and parsing options
// ABOUTME: Provides configurable annotation namespace and parsing behavior
package plugin

// Linker flag variables for backward compatibility
var (
	// AnnotationPrefix can still be set via linker flags as fallback
	AnnotationPrefix = "vnd.obsidian.plugin"
)

// PluginOpts configures plugin metadata parsing behavior
type PluginOpts struct {
	// Annotation namespace prefix (default: "vnd.obsidian.plugin")
	AnnotationNamespace string

	// Trusted workflow signer identity for provenance verification
	TrustedWorkflowSigner string

	// Validation strictness level
	StrictValidation bool
}

// DefaultPluginOpts returns default plugin parsing options
func DefaultPluginOpts() *PluginOpts {
	return &PluginOpts{
		AnnotationNamespace: getDefaultAnnotationNamespace(),
		StrictValidation:    false,
	}
}

// WithAnnotationNamespace sets a custom annotation namespace
func (opts *PluginOpts) WithAnnotationNamespace(namespace string) *PluginOpts {
	opts.AnnotationNamespace = namespace
	return opts
}

// WithTrustedWorkflowSigner sets the trusted workflow signer
func (opts *PluginOpts) WithTrustedWorkflowSigner(signer string) *PluginOpts {
	opts.TrustedWorkflowSigner = signer
	return opts
}

// WithStrictValidation enables/disables strict validation
func (opts *PluginOpts) WithStrictValidation(strict bool) *PluginOpts {
	opts.StrictValidation = strict
	return opts
}

// getDefaultAnnotationNamespace returns the default namespace, respecting linker flags
func getDefaultAnnotationNamespace() string {
	if AnnotationPrefix != "" {
		return AnnotationPrefix
	}
	return "vnd.obsidian.plugin"
}

// GetAnnotationKey returns the full annotation key with the configured prefix
func GetAnnotationKey(field string) string {
	return getDefaultAnnotationNamespace() + "." + field
}

// GetAnnotationKeyWithNamespace returns the annotation key with a specific namespace
func GetAnnotationKeyWithNamespace(namespace, field string) string {
	return namespace + "." + field
}

// Annotation key constants for the legacy manifest.json fields
const (
	AnnotationID            = "id"
	AnnotationName          = "name"
	AnnotationVersion       = "version"
	AnnotationMinAppVersion = "minAppVersion"
	AnnotationDescription   = "description"
	AnnotationAuthor        = "author"
	AnnotationAuthorURL     = "authorUrl"
	AnnotationIsDesktopOnly = "isDesktopOnly"
)