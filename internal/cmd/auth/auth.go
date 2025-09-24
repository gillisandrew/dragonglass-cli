// ABOUTME: Authentication command for GitHub App device flow
// ABOUTME: Handles user authentication to access ghcr.io registry
package auth

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gillisandrew/dragonglass-cli/internal/config"
	"github.com/gillisandrew/dragonglass-cli/internal/lockfile"
)

func NewAuthCommand(cfg *config.Config, configPath string, configErr error, lockfileData *lockfile.Lockfile, lockfilePath string, lockfileErr error) *cobra.Command {
	return &cobra.Command{
		Use:   "auth",
		Short: "Authenticate with GitHub App using device flow",
		Long: `Authenticate with GitHub App to access ghcr.io registry.
This command will guide you through the OAuth device flow process
and securely store your authentication credentials.`,
		Run: func(cmd *cobra.Command, args []string) {
			if configErr != nil {
				fmt.Printf("Warning: Failed to load configuration: %v\n", configErr)
				fmt.Println("Using default configuration...")
				cfg = config.DefaultConfig()
			}

			fmt.Println("auth command called")
			fmt.Printf("Using registry: %s\n", cfg.Registry.DefaultRegistry)
			fmt.Printf("Config loaded from: %s\n", configPath)
			fmt.Println("This will implement GitHub App device flow authentication")
		},
	}
}