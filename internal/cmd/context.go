// ABOUTME: Shared command context structure for CLI commands
// ABOUTME: Contains global configuration that can be passed to all commands
package cmd

// CommandContext holds global configuration that can be passed to commands
type CommandContext struct {
	AnnotationNamespace string
	TrustedBuilder      string
	ConfigPath          string
	LockfilePath        string
	GitHubToken         string
}
