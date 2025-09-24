// ABOUTME: List command for displaying installed verified plugins
// ABOUTME: Shows plugins from lockfile with their verification status
package list

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gillisandrew/dragonglass-cli/internal/config"
)

func NewListCommand(cfg *config.Config, configPath string, configErr error) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List installed verified plugins",
		Long: `List all plugins installed through dragonglass in the current vault.
Displays plugin names, versions, installation status, and verification details
from the lockfile.`,
		Run: func(cmd *cobra.Command, args []string) {
			if configErr != nil {
				fmt.Printf("Warning: Failed to load configuration: %v\n", configErr)
				fmt.Println("Using default configuration...")
				cfg = config.DefaultConfig()
			}

			fmt.Println("list command called")
			fmt.Printf("Output format: %s (color=%v)\n", cfg.Output.Format, cfg.Output.Color)
			fmt.Printf("Config loaded from: %s\n", configPath)
			fmt.Println("This will implement plugin listing from lockfile")
		},
	}
}