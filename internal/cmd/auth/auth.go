// ABOUTME: Authentication command for GitHub App device flow
// ABOUTME: Handles user authentication to access ghcr.io registry
package auth

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gillisandrew/dragonglass-cli/internal/auth"
	"github.com/gillisandrew/dragonglass-cli/internal/cmd"
	"github.com/gillisandrew/dragonglass-cli/internal/config"
)

func NewAuthCommand(ctx *cmd.CommandContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate with GitHub App using device flow",
		Long: `Authenticate with GitHub App to access ghcr.io registry.
This command will guide you through the OAuth device flow process
and securely store your authentication credentials.

The authentication uses the same proven flow as the GitHub CLI (gh).`,
		Run: func(cmd *cobra.Command, args []string) {
			err := runAuthCommand(ctx)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}
		},
	}

	cmd.AddCommand(newStatusCommand())
	cmd.AddCommand(newLogoutCommand())

	return cmd
}

func runAuthCommand(ctx *cmd.CommandContext) error {
	// Configure auth client with token override if provided
	authOpts := auth.DefaultAuthOpts()
	if ctx.GitHubToken != "" {
		authOpts = authOpts.WithToken(ctx.GitHubToken)
	}
	authClient := auth.NewAuthClient(authOpts)

	// Check if already authenticated
	if authClient.IsAuthenticated() {
		username, err := auth.GetAuthenticatedUser()
		if err != nil {
			// Don't fail completely if we can't get username details
			username = "authenticated user"
		}

		// Load configuration to show registry
		configOpts := config.DefaultConfigOpts()
		if ctx.ConfigPath != "" {
			configOpts = configOpts.WithConfigPath(ctx.ConfigPath)
		}
		configManager := config.NewConfigManager(configOpts)
		cfg, _, err := configManager.LoadConfig()
		if err != nil {
			cfg = config.DefaultConfig()
		}

		fmt.Printf("✅ Already authenticated as %s\n", username)
		fmt.Printf("📦 Registry: %s\n", cfg.Registry.DefaultRegistry)
		fmt.Println("\nUse 'dragonglass auth status' to view details.")
		return nil
	}

	// Run device flow authentication
	return auth.Authenticate()
}

func newStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "View authentication status",
		Long:  `Display current authentication status and user information.`,
		Run: func(cmd *cobra.Command, args []string) {
			if !auth.IsAuthenticated() {
				fmt.Printf("❌ Not authenticated with %s\n", auth.DefaultGitHubHost)
				fmt.Println("\nRun 'dragonglass auth' to authenticate.")
				return
			}

			username, err := auth.GetAuthenticatedUser()
			if err != nil {
				username = "authenticated user"
			}

			token, err := auth.GetToken()
			if err != nil {
				fmt.Printf("Error getting token: %v\n", err)
				return
			}

			// Get stored credential details
			cred, err := auth.GetStoredCredential()
			if err != nil {
				fmt.Printf("Error getting credential details: %v\n", err)
				return
			}

			// Don't show full token for security
			maskedToken := maskToken(token)

			fmt.Printf("✅ Authenticated with %s\n", auth.DefaultGitHubHost)
			fmt.Printf("👤 User: %s\n", username)
			fmt.Printf("🔑 Token: %s\n", maskedToken)
			fmt.Printf("📦 Scopes: %s\n", cred.Scopes)
			fmt.Printf("📦 Can access: ghcr.io (GitHub Container Registry)\n")
			fmt.Printf("🔧 Source: %s\n", cred.Source)
			fmt.Printf("📅 Created: %s\n", cred.CreatedAt.Format("2006-01-02 15:04:05"))
		},
	}
}

func newLogoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Sign out and remove stored credentials",
		Long:  `Remove stored authentication credentials and sign out.`,
		Run: func(cmd *cobra.Command, args []string) {
			if !auth.IsAuthenticated() {
				fmt.Printf("❌ Not currently authenticated\n")
				return
			}

			// Get username before logout for confirmation
			username, _ := auth.GetAuthenticatedUser()
			if username == "" {
				username = "authenticated user"
			}

			// Clear stored credentials
			if err := auth.ClearStoredToken(); err != nil {
				fmt.Printf("Error clearing credentials: %v\n", err)
				return
			}

			fmt.Printf("✅ Successfully logged out %s\n", username)
			fmt.Printf("🗑️  All stored credentials have been removed\n")
		},
	}
}

func maskToken(token string) string {
	if len(token) <= 8 {
		return "********"
	}
	return token[:4] + "..." + token[len(token)-4:]
}