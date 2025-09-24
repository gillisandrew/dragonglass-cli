// ABOUTME: List command for displaying installed verified plugins
// ABOUTME: Shows plugins from lockfile with their verification status
package list

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/gillisandrew/dragonglass-cli/internal/cmd"
	"github.com/gillisandrew/dragonglass-cli/internal/config"
	"github.com/gillisandrew/dragonglass-cli/internal/lockfile"
)

func NewListCommand(ctx *cmd.CommandContext) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List installed verified plugins",
		Long: `List all plugins installed through dragonglass in the current vault.
Displays plugin names, versions, installation status, and verification details
from the lockfile.`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := runListCommand(ctx); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
}

func runListCommand(ctx *cmd.CommandContext) error {
	// Load configuration
	configOpts := config.DefaultConfigOpts()
	if ctx.ConfigPath != "" {
		configOpts = configOpts.WithConfigPath(ctx.ConfigPath)
	}
	configManager := config.NewConfigManager(configOpts)
	cfg, _, err := configManager.LoadConfig()
	if err != nil {
		fmt.Printf("Warning: Failed to load configuration: %v\n", err)
		fmt.Println("Using default configuration...")
		cfg = config.DefaultConfig()
	}

	// Find dragonglass directory and load lockfile (same logic as install/add commands)
	dragonglassDir, err := findDragonglassDirectory()
	if err != nil {
		return fmt.Errorf("failed to find dragonglass directory: %w", err)
	}

	lockfilePath := filepath.Join(dragonglassDir, "dragonglass-lock.json")

	// Check if lockfile exists
	if _, err := os.Stat(lockfilePath); os.IsNotExist(err) {
		return fmt.Errorf("no lockfile found at %s (run 'dragonglass add' to add plugins first)", lockfilePath)
	}

	// Load existing lockfile
	lockfileData, err := lockfile.LoadLockfile(lockfilePath)
	if err != nil {
		return fmt.Errorf("failed to load lockfile: %w", err)
	}

	plugins := lockfileData.ListPlugins()
	if len(plugins) == 0 {
		fmt.Println("No verified plugins installed in this vault.")
		return nil
	}

	if cfg.Output.Format == "json" {
		fmt.Printf("JSON output not yet implemented. Found %d plugins.\n", len(plugins))
		return nil
	}

	// Text output with table format
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "NAME\tVERSION\tVERIFIED\tSTATUS"); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if _, err := fmt.Fprintln(w, "----\t-------\t--------\t------"); err != nil {
		return fmt.Errorf("failed to write header separator: %w", err)
	}

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

		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			plugin.Name,
			plugin.Version,
			verifiedStatus,
			status); err != nil {
			return fmt.Errorf("failed to write plugin row: %w", err)
		}
	}

	if err := w.Flush(); err != nil {
		return fmt.Errorf("failed to flush table output: %w", err)
	}

	fmt.Printf("\nTotal: %d verified plugins\n", len(plugins))
	fmt.Printf("Lockfile: %s\n", lockfilePath)

	return nil
}

// findDragonglassDirectory searches for or creates .dragonglass directory from current directory up
func findDragonglassDirectory() (string, error) {
	currentDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %w", err)
	}

	// Search up the directory tree for .dragonglass or create it at the same level as .obsidian
	for {
		// Check if .obsidian exists to determine if this is an Obsidian vault
		obsidianPath := filepath.Join(currentDir, ".obsidian")
		if info, err := os.Stat(obsidianPath); err == nil && info.IsDir() {
			// Found .obsidian, so create/use .dragonglass at the same level
			dragonglassPath := filepath.Join(currentDir, ".dragonglass")

			// Create .dragonglass directory if it doesn't exist
			if err := os.MkdirAll(dragonglassPath, 0755); err != nil {
				return "", fmt.Errorf("failed to create .dragonglass directory: %w", err)
			}

			return dragonglassPath, nil
		}

		parent := filepath.Dir(currentDir)
		if parent == currentDir {
			break // reached root
		}
		currentDir = parent
	}

	return "", fmt.Errorf(".obsidian directory not found in current path or parent directories (required to determine vault location)")
}