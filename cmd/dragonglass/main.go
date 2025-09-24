// ABOUTME: Main entry point for the dragonglass CLI application
// ABOUTME: Sets up the root command and executes the CLI
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/gillisandrew/dragonglass-cli/internal/cmd"
	"github.com/gillisandrew/dragonglass-cli/internal/cmd/auth"
	"github.com/gillisandrew/dragonglass-cli/internal/cmd/install"
	"github.com/gillisandrew/dragonglass-cli/internal/cmd/list"
	"github.com/gillisandrew/dragonglass-cli/internal/cmd/verify"
)

var (
	// Global flags
	annotationNamespace string
	trustedBuilder      string
	configPath          string
	lockfilePath        string
	githubToken         string
)

var rootCmd = &cobra.Command{
	Use:   "dragonglass",
	Short: "A secure Obsidian plugin manager with provenance verification",
	Long: `Dragonglass is a CLI tool that provides secure plugin management for Obsidian
by verifying provenance attestations and Software Bill of Materials (SBOM).

It ensures plugins are built through authorized workflows and performs
vulnerability scanning before installation.`,
}

func init() {
	// Global persistent flags
	rootCmd.PersistentFlags().StringVar(&annotationNamespace, "annotation-namespace", "vnd.obsidian.plugin", "Plugin annotation namespace prefix")
	rootCmd.PersistentFlags().StringVar(&trustedBuilder, "trusted-builder", "https://github.com/gillisandrew/dragonglass-poc/.github/workflows/build.yml@refs/heads/main", "Trusted workflow signer identity")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to configuration file")
	rootCmd.PersistentFlags().StringVar(&lockfilePath, "lockfile", "", "Path to lockfile")
	rootCmd.PersistentFlags().StringVar(&githubToken, "github-token", "", "GitHub authentication token")
}

func main() {
	// Initialize command context with global flags
	cmdContext := &cmd.CommandContext{
		AnnotationNamespace: annotationNamespace,
		TrustedBuilder:      trustedBuilder,
		ConfigPath:          configPath,
		LockfilePath:        lockfilePath,
		GitHubToken:         githubToken,
	}

	// Add commands with context
	rootCmd.AddCommand(auth.NewAuthCommand(cmdContext))
	rootCmd.AddCommand(install.NewInstallCommand(cmdContext))
	rootCmd.AddCommand(verify.NewVerifyCommand(cmdContext))
	rootCmd.AddCommand(list.NewListCommand(cmdContext))

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
