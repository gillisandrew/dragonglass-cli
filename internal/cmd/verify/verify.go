// ABOUTME: Verify command for checking plugin security without installation
// ABOUTME: Performs verification checks and displays results without installing
package verify

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/gillisandrew/dragonglass-cli/internal/attestation"
	"github.com/gillisandrew/dragonglass-cli/internal/auth"
	"github.com/gillisandrew/dragonglass-cli/internal/config"
	"github.com/gillisandrew/dragonglass-cli/internal/lockfile"
	"github.com/gillisandrew/dragonglass-cli/internal/plugin"
	"github.com/gillisandrew/dragonglass-cli/internal/registry"
)

func NewVerifyCommand(cfg *config.Config, configPath string, configErr error, lockfileData *lockfile.Lockfile, lockfilePath string, lockfileErr error) *cobra.Command {
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
			fmt.Printf("🔍 Verifying plugin: %s\n", imageRef)
			fmt.Printf("Verification mode: strict=%v\n", cfg.Verification.StrictMode)

			if err := verifyPlugin(imageRef, cfg); err != nil {
				fmt.Printf("❌ Verification failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("✅ Plugin verification completed successfully\n")
		},
	}
}

func verifyPlugin(imageRef string, cfg *config.Config) error {
	fmt.Printf("📋 Creating registry client...\n")

	// Create registry client
	client, err := registry.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create registry client: %w", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Printf("🌐 Fetching manifest from registry...\n")

	// Get manifest and annotations
	manifest, annotations, err := client.GetManifest(ctx, imageRef)
	if err != nil {
		return fmt.Errorf("failed to fetch manifest: %w", err)
	}

	fmt.Printf("📦 Manifest retrieved successfully\n")
	fmt.Printf("   - Config size: %d bytes\n", manifest.Config.Size)
	fmt.Printf("   - Layers: %d\n", len(manifest.Layers))
	fmt.Printf("   - Annotations: %d\n", len(annotations))

	// Parse plugin metadata from annotations
	fmt.Printf("🔍 Parsing plugin metadata...\n")
	parser := plugin.NewManifestParser()
	pluginMetadata, err := parser.ParseMetadata(manifest, annotations)
	if err != nil {
		return fmt.Errorf("failed to parse plugin metadata: %w", err)
	}

	// Display plugin information
	fmt.Printf("📋 Plugin Information:\n")
	fmt.Printf("   - Name: %s\n", pluginMetadata.Name)
	fmt.Printf("   - Version: %s\n", pluginMetadata.Version)
	fmt.Printf("   - Author: %s\n", pluginMetadata.Author)
	fmt.Printf("   - Description: %s\n", pluginMetadata.Description)

	if pluginMetadata.MinAppVersion != "" {
		fmt.Printf("   - Min App Version: %s\n", pluginMetadata.MinAppVersion)
	}

	if pluginMetadata.AuthorURL != "" {
		fmt.Printf("   - Author URL: %s\n", pluginMetadata.AuthorURL)
	}

	// Show raw annotations for debugging
	if len(annotations) > 0 {
		fmt.Printf("📝 Raw Annotations:\n")
		for key, value := range annotations {
			fmt.Printf("   - %s: %s\n", key, value)
		}
	}

	// Validate metadata
	fmt.Printf("✅ Validating plugin metadata...\n")
	validation := parser.ValidateMetadata(pluginMetadata)

	if !validation.Valid {
		fmt.Printf("❌ Metadata validation failed:\n")
		for _, err := range validation.Errors {
			fmt.Printf("   - Error: %s\n", err)
		}
		if !cfg.Verification.StrictMode {
			fmt.Printf("⚠️  Continuing in non-strict mode\n")
		} else {
			return fmt.Errorf("metadata validation failed in strict mode")
		}
	}

	if len(validation.Warnings) > 0 {
		fmt.Printf("⚠️  Metadata warnings:\n")
		for _, warning := range validation.Warnings {
			fmt.Printf("   - Warning: %s\n", warning)
		}
	}

	fmt.Printf("🎯 Basic verification completed\n")

	// Get GitHub token for attestation verification
	fmt.Printf("🔐 Getting authentication token...\n")
	token, err := auth.GetToken()
	if err != nil {
		return fmt.Errorf("failed to get authentication token for attestation verification: %w", err)
	}

	// Verify SLSA provenance attestation
	fmt.Printf("🔍 Verifying SLSA provenance attestation...\n")
	slsaVerifier := attestation.NewSLSAVerifier(token)
	attestationResult, err := slsaVerifier.VerifyAttestation(ctx, imageRef)
	if err != nil {
		return fmt.Errorf("failed to verify SLSA attestation: %w", err)
	}

	// Display debug warnings first
	if len(attestationResult.Warnings) > 0 {
		fmt.Printf("⚠️  Debug information:\n")
		for _, warning := range attestationResult.Warnings {
			fmt.Printf("   - %s\n", warning)
		}
	}

	// Display attestation verification results
	fmt.Print(slsaVerifier.FormatVerificationResult(attestationResult))

	// Check if attestation verification should block installation
	if cfg.Verification.StrictMode && (!attestationResult.Found || !attestationResult.Valid) {
		if !attestationResult.Found {
			return fmt.Errorf("SLSA attestation not found (required in strict mode)")
		}
		if !attestationResult.Valid {
			return fmt.Errorf("SLSA attestation verification failed (required in strict mode)")
		}
	}

	fmt.Printf("📄 Note: SBOM verification not yet implemented\n")

	return nil
}