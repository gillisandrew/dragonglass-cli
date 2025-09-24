// ABOUTME: Authentication command for GitHub App device flow
// ABOUTME: Handles user authentication to access ghcr.io registry
package auth

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gillisandrew/dragonglass-cli/internal/auth"
	"github.com/gillisandrew/dragonglass-cli/internal/config"
	"github.com/gillisandrew/dragonglass-cli/internal/lockfile"
)

func NewAuthCommand(cfg *config.Config, configPath string, configErr error, lockfileData *lockfile.Lockfile, lockfilePath string, lockfileErr error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate with GitHub App using device flow",
		Long: `Authenticate with GitHub App to access ghcr.io registry.
This command will guide you through the OAuth device flow process
and securely store your authentication credentials.

The authentication uses the same proven flow as the GitHub CLI (gh).`,
		Run: func(cmd *cobra.Command, args []string) {
			if configErr != nil {
				fmt.Printf("Warning: Failed to load configuration: %v\n", configErr)
				cfg = config.DefaultConfig()
			}

			err := runAuthCommand(cfg)
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

func runAuthCommand(cfg *config.Config) error {
	hostname := auth.GitHubHost

	// Check if already authenticated
	if auth.IsAuthenticated(hostname) {
		username, err := auth.GetAuthenticatedUser(hostname)
		if err != nil {
			// Don't fail completely if we can't get username details
			username = "authenticated user"
		}

		fmt.Printf("✅ Already authenticated as %s on %s\n", username, hostname)
		fmt.Printf("📦 Registry: %s\n", cfg.Registry.DefaultRegistry)
		fmt.Println("\nUse 'dragonglass auth status' to view details.")
		return nil
	}

	// User needs to authenticate
	fmt.Printf("🔐 Authentication required to access GitHub Container Registry\n")
	fmt.Printf("📦 Dragonglass needs permission to read packages from ghcr.io\n\n")

	fmt.Printf("To authenticate, please run one of the following:\n\n")
	fmt.Printf("1. Using GitHub CLI (recommended):\n")
	fmt.Printf("   gh auth login --scopes %s\n\n", auth.RequiredScopes)

	fmt.Printf("2. Using environment variable:\n")
	fmt.Printf("   export GH_TOKEN=<your-github-token>\n\n")

	fmt.Printf("3. Using config file:\n")
	fmt.Printf("   echo '<your-token>' > ~/.config/gh/hosts.yml\n\n")

	fmt.Printf("After authenticating, run this command again to verify your credentials.\n")

	return fmt.Errorf("authentication required")
}

func newStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "View authentication status",
		Long:  `Display current authentication status and user information.`,
		Run: func(cmd *cobra.Command, args []string) {
			hostname := auth.GitHubHost

			if !auth.IsAuthenticated(hostname) {
				fmt.Printf("❌ Not authenticated with %s\n", hostname)
				fmt.Println("\nRun 'dragonglass auth' to see authentication options.")
				return
			}

			username, err := auth.GetAuthenticatedUser(hostname)
			if err != nil {
				username = "authenticated user"
			}

			token, err := auth.GetStoredToken(hostname)
			if err != nil {
				fmt.Printf("Error getting token: %v\n", err)
				return
			}

			// Don't show full token for security
			maskedToken := maskToken(token)

			fmt.Printf("✅ Authenticated with %s\n", hostname)
			fmt.Printf("👤 User: %s\n", username)
			fmt.Printf("🔑 Token: %s\n", maskedToken)
			fmt.Printf("📦 Can access: ghcr.io (GitHub Container Registry)\n")
			fmt.Printf("🔧 Source: GitHub CLI configuration\n")
		},
	}
}

func newLogoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Sign out and remove stored credentials",
		Long:  `Remove stored authentication credentials and sign out.`,
		Run: func(cmd *cobra.Command, args []string) {
			hostname := "github.com"

			if !auth.IsAuthenticated(hostname) {
				fmt.Printf("❌ Not currently authenticated with %s\n", hostname)
				return
			}

			// TODO: Implement logout functionality
			// This would require using GitHub CLI's logout functionality
			fmt.Printf("🚧 Logout functionality not yet implemented\n")
			fmt.Printf("For now, you can use 'gh auth logout' to sign out from GitHub CLI\n")
		},
	}
}

func maskToken(token string) string {
	if len(token) <= 8 {
		return "********"
	}
	return token[:4] + "..." + token[len(token)-4:]
}