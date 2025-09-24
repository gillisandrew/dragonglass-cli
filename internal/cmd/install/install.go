// ABOUTME: Install command for verified Obsidian plugins
// ABOUTME: Downloads, verifies, and installs plugins from OCI registry
package install

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gillisandrew/dragonglass-cli/internal/config"
	"github.com/gillisandrew/dragonglass-cli/internal/lockfile"
)

func NewInstallCommand(cfg *config.Config, configPath string, configErr error, lockfileData *lockfile.Lockfile, lockfilePath string, lockfileErr error) *cobra.Command {
	return &cobra.Command{
		Use:   "install [OCI_IMAGE_REFERENCE]",
		Short: "Install a verified plugin from OCI registry",
		Long: `Install a verified Obsidian plugin from an OCI registry.
The plugin will be downloaded, verified for provenance and vulnerabilities,
and installed to the .obsidian/plugins/ directory after user confirmation.

Example:
  dragonglass install ghcr.io/owner/repo:plugin-name-v1.0.0`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if configErr != nil {
				fmt.Printf("Warning: Failed to load configuration: %v\n", configErr)
				fmt.Println("Using default configuration...")
				cfg = config.DefaultConfig()
			}

			imageRef := args[0]
			fmt.Printf("install command called with image: %s\n", imageRef)
			fmt.Printf("Verification settings: strict=%v, skip_vuln=%v\n",
				cfg.Verification.StrictMode, cfg.Verification.SkipVulnScan)
			fmt.Printf("Output format: %s (verbose=%v, color=%v)\n",
				cfg.Output.Format, cfg.Output.Verbose, cfg.Output.Color)
			fmt.Printf("Config loaded from: %s\n", configPath)
			fmt.Println("This will implement plugin verification and installation")
		},
	}
}