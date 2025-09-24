// ABOUTME: Verify command for checking plugin security without installation
// ABOUTME: Performs verification checks and displays results without installing
package verify

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gillisandrew/dragonglass-cli/internal/config"
)

func NewVerifyCommand(cfg *config.Config, configPath string, configErr error) *cobra.Command {
	return &cobra.Command{
		Use:   "verify [OCI_IMAGE_REFERENCE]",
		Short: "Verify a plugin without installing it",
		Long: `Verify an Obsidian plugin's provenance and security without installation.
This command downloads and verifies SLSA attestations, SBOM data, and
vulnerability information, then displays the results.

Example:
  dragonglass verify ghcr.io/owner/repo:plugin-name-v1.0.0`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if configErr != nil {
				fmt.Printf("Warning: Failed to load configuration: %v\n", configErr)
				fmt.Println("Using default configuration...")
				cfg = config.DefaultConfig()
			}

			imageRef := args[0]
			fmt.Printf("verify command called with image: %s\n", imageRef)
			fmt.Printf("Verification mode: strict=%v\n", cfg.Verification.StrictMode)
			fmt.Printf("Config loaded from: %s\n", configPath)
			fmt.Println("This will implement verification-only workflow")
		},
	}
}