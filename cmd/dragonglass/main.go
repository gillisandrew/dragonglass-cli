// ABOUTME: Main entry point for the dragonglass CLI application
// ABOUTME: Sets up the root command and executes the CLI
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/gillisandrew/dragonglass-cli/internal/cmd/auth"
	"github.com/gillisandrew/dragonglass-cli/internal/cmd/install"
	"github.com/gillisandrew/dragonglass-cli/internal/cmd/list"
	"github.com/gillisandrew/dragonglass-cli/internal/cmd/verify"
	"github.com/gillisandrew/dragonglass-cli/internal/config"
	"github.com/gillisandrew/dragonglass-cli/internal/lockfile"
)

var rootCmd = &cobra.Command{
	Use:   "dragonglass",
	Short: "A secure Obsidian plugin manager with provenance verification",
	Long: `Dragonglass is a CLI tool that provides secure plugin management for Obsidian
by verifying provenance attestations and Software Bill of Materials (SBOM).

It ensures plugins are built through authorized workflows and performs
vulnerability scanning before installation.`,
}

func main() {
	// Try to load configuration from current directory
	// Commands will gracefully handle missing config
	cfg, configPath, configErr := config.LoadFromCurrentDirectory()

	// Try to load lockfile from the same .obsidian directory
	var lockfileData *lockfile.Lockfile
	var lockfilePath string
	var lockfileErr error

	if configErr == nil {
		// Extract obsidian directory from config path
		obsidianDir := filepath.Dir(configPath)
		lockfileData, lockfilePath, lockfileErr = lockfile.LoadFromObsidianDirectory(obsidianDir)
	}

	rootCmd.AddCommand(auth.NewAuthCommand(cfg, configPath, configErr, lockfileData, lockfilePath, lockfileErr))
	rootCmd.AddCommand(install.NewInstallCommand(cfg, configPath, configErr, lockfileData, lockfilePath, lockfileErr))
	rootCmd.AddCommand(verify.NewVerifyCommand(cfg, configPath, configErr, lockfileData, lockfilePath, lockfileErr))
	rootCmd.AddCommand(list.NewListCommand(cfg, configPath, configErr, lockfileData, lockfilePath, lockfileErr))

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}