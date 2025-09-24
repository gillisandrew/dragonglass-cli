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
	"github.com/gillisandrew/dragonglass-cli/internal/cmd"
	"github.com/gillisandrew/dragonglass-cli/internal/config"
	"github.com/gillisandrew/dragonglass-cli/internal/plugin"
	"github.com/gillisandrew/dragonglass-cli/internal/registry"
)

func NewVerifyCommand(ctx *cmd.CommandContext) *cobra.Command {
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
			imageRef := args[0]
			fmt.Printf("Verifying plugin: %s\n", imageRef)

			if err := verifyPlugin(imageRef, ctx); err != nil {
				fmt.Printf("Verification failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Plugin verification completed successfully\n")
		},
	}
}

func verifyPlugin(imageRef string, ctx *cmd.CommandContext) error {
	fmt.Printf("Creating registry client...\n")

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

	fmt.Printf("Verification mode: strict=%v\n", cfg.Verification.StrictMode)

	// Configure registry client
	registryOpts := registry.DefaultRegistryOpts()
	if cfg.Registry.DefaultRegistry != "" {
		registryOpts = registryOpts.WithRegistryHost(cfg.Registry.DefaultRegistry)
	}

	// Configure auth if token provided via flag
	if ctx.GitHubToken != "" {
		authOpts := auth.DefaultAuthOpts().WithToken(ctx.GitHubToken)
		authClient := auth.NewAuthClient(authOpts)
		registryOpts = registryOpts.WithAuthProvider(authClient)
	}

	// Create registry client
	client, err := registry.NewClient(registryOpts)
	if err != nil {
		return fmt.Errorf("failed to create registry client: %w", err)
	}

	// Create context with timeout
	opCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Printf("Fetching manifest from registry...\n")

	// Get manifest and annotations
	manifest, annotations, err := client.GetManifest(opCtx, imageRef)
	if err != nil {
		return fmt.Errorf("failed to fetch manifest: %w", err)
	}

	fmt.Printf("📦 Manifest retrieved successfully\n")
	fmt.Printf("   - Config size: %d bytes\n", manifest.Config.Size)
	fmt.Printf("   - Layers: %d\n", len(manifest.Layers))
	fmt.Printf("   - Annotations: %d\n", len(annotations))

	// Parse plugin metadata from annotations
	fmt.Printf("Parsing plugin metadata...\n")

	// Configure plugin parser with annotation namespace from context
	pluginOpts := plugin.DefaultPluginOpts()
	if ctx.AnnotationNamespace != "" {
		pluginOpts = pluginOpts.WithAnnotationNamespace(ctx.AnnotationNamespace)
	}
	if ctx.TrustedBuilder != "" {
		pluginOpts = pluginOpts.WithTrustedWorkflowSigner(ctx.TrustedBuilder)
	}
	if cfg.Verification.StrictMode {
		pluginOpts = pluginOpts.WithStrictValidation(true)
	}

	parser := plugin.NewManifestParser(pluginOpts)
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

	// Verify all attestations (SLSA, SBOM, etc.)
	fmt.Printf("🔍 Verifying attestations (SLSA, SBOM, etc.)...\n")
	verifier, err := attestation.NewAttestationVerifier(token, ctx.TrustedBuilder)
	if err != nil {
		return fmt.Errorf("failed to create attestation verifier: %w", err)
	}

	attestationResult, err := verifier.VerifyAttestations(opCtx, imageRef)
	if err != nil {
		return fmt.Errorf("failed to verify attestations: %w", err)
	}

	// Display debug warnings first
	if len(attestationResult.Warnings) > 0 {
		fmt.Printf("⚠️  Debug information:\n")
		for _, warning := range attestationResult.Warnings {
			fmt.Printf("   - %s\n", warning)
		}
	}

	// Display attestation verification results
	fmt.Print(verifier.FormatVerificationResult(attestationResult))

	// Check if attestation verification should block installation
	if cfg.Verification.StrictMode && (!attestationResult.Found || !attestationResult.Valid) {
		if !attestationResult.Found {
			return fmt.Errorf("attestations not found (required in strict mode)")
		}
		if !attestationResult.Valid {
			return fmt.Errorf("attestation verification failed (required in strict mode)")
		}
	}

	// Additional SBOM-specific security checks
	if attestationResult.SBOM != nil && len(attestationResult.SBOM.Vulnerabilities) > 0 {
		highSeverityVulns := 0
		for _, vuln := range attestationResult.SBOM.Vulnerabilities {
			if vuln.Severity == "HIGH" || vuln.Severity == "CRITICAL" {
				highSeverityVulns++
			}
		}

		if highSeverityVulns > 0 {
			fmt.Printf("⚠️  Found %d high/critical severity vulnerabilities\n", highSeverityVulns)
			if cfg.Verification.StrictMode {
				return fmt.Errorf("%d high/critical vulnerabilities found (blocked in strict mode)", highSeverityVulns)
			}
		}
	}

	return nil
}
