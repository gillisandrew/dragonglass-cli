// ABOUTME: List command for displaying installed verified plugins
// ABOUTME: Shows plugins from lockfile with their verification status
package list

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/gillisandrew/dragonglass-cli/internal/config"
	"github.com/gillisandrew/dragonglass-cli/internal/lockfile"
)

func NewListCommand(cfg *config.Config, configPath string, configErr error, lockfileData *lockfile.Lockfile, lockfilePath string, lockfileErr error) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List installed verified plugins",
		Long: `List all plugins installed through dragonglass in the current vault.
Displays plugin names, versions, installation status, and verification details
from the lockfile.`,
		Run: func(cmd *cobra.Command, args []string) {
			if configErr != nil {
				fmt.Printf("Warning: Failed to load configuration: %v\n", configErr)
				cfg = config.DefaultConfig()
			}

			if lockfileErr != nil {
				fmt.Printf("Error: Failed to load lockfile: %v\n", lockfileErr)
				return
			}

			plugins := lockfileData.ListPlugins()
			if len(plugins) == 0 {
				fmt.Println("No verified plugins installed in this vault.")
				return
			}

			if cfg.Output.Format == "json" {
				// TODO: Implement JSON output
				fmt.Printf("JSON output not yet implemented. Found %d plugins.\n", len(plugins))
				return
			}

			// Text output with table format
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tVERSION\tINSTALLED\tVERIFIED\tSTATUS")
			fmt.Fprintln(w, "----\t-------\t---------\t--------\t------")

			for _, plugin := range plugins {
				status := "✓ OK"
				if len(plugin.VerificationState.Errors) > 0 {
					status = "✗ ERROR"
				} else if len(plugin.VerificationState.Warnings) > 0 {
					status = "⚠ WARNING"
				}

				verifiedStatus := "No"
				if plugin.VerificationState.ProvenanceVerified && plugin.VerificationState.SBOMVerified {
					verifiedStatus = "Yes"
				}

				installTime := plugin.InstallTime.Format("2006-01-02")

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					plugin.Name,
					plugin.Version,
					installTime,
					verifiedStatus,
					status)
			}

			w.Flush()

			fmt.Printf("\nTotal: %d verified plugins\n", len(plugins))
			if lockfilePath != "" {
				fmt.Printf("Lockfile: %s\n", lockfilePath)
			}
		},
	}
}