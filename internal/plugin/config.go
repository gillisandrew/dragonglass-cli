// ABOUTME: Build-time configuration for plugin annotation namespaces
// ABOUTME: Uses linker flags to set annotation prefixes at compile time
package plugin

// These variables are set via linker flags during build time
// Example: go build -ldflags "-X 'github.com/gillisandrew/dragonglass-cli/internal/plugin.AnnotationPrefix=vnd.obsidian.plugin'"
var (
	// AnnotationPrefix is the namespace prefix for plugin annotations
	// Default: "vnd.obsidian.plugin" but can be overridden at build time
	AnnotationPrefix = "vnd.obsidian.plugin"
)

// GetAnnotationKey returns the full annotation key with the configured prefix
func GetAnnotationKey(field string) string {
	return AnnotationPrefix + "." + field
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