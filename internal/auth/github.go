// ABOUTME: GitHub authentication using native device flow implementation
// ABOUTME: Provides unified authentication interface for dragonglass CLI
package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	// Default GitHub configuration for dragonglass
	DefaultGitHubHost = "github.com"

	// Default OAuth Scopes needed for ghcr.io access
	DefaultRequiredScopes = "read:packages"
)

// AuthOpts configures GitHub authentication behavior
type AuthOpts struct {
	// GitHub hostname (default: "github.com")
	GitHubHost string

	// Required OAuth scopes (default: "read:packages")
	RequiredScopes string

	// Override token (for testing or custom auth)
	Token string
}

// DefaultAuthOpts returns the default authentication options
func DefaultAuthOpts() *AuthOpts {
	return &AuthOpts{
		GitHubHost:     DefaultGitHubHost,
		RequiredScopes: DefaultRequiredScopes,
	}
}

// WithToken sets a custom authentication token
func (opts *AuthOpts) WithToken(token string) *AuthOpts {
	opts.Token = token
	return opts
}

// WithHost sets a custom GitHub hostname
func (opts *AuthOpts) WithHost(host string) *AuthOpts {
	opts.GitHubHost = host
	return opts
}

// WithScopes sets custom OAuth scopes
func (opts *AuthOpts) WithScopes(scopes string) *AuthOpts {
	opts.RequiredScopes = scopes
	return opts
}

// AuthClient provides GitHub authentication functionality
type AuthClient struct {
	opts *AuthOpts
}

// NewAuthClient creates a new authentication client with the given options
func NewAuthClient(opts *AuthOpts) *AuthClient {
	if opts == nil {
		opts = DefaultAuthOpts()
	}
	return &AuthClient{opts: opts}
}

// IsAuthenticated checks if user has valid stored credentials
func (c *AuthClient) IsAuthenticated() bool {
	// If token override is provided, validate it directly
	if c.opts.Token != "" {
		return c.ValidateToken(c.opts.Token) == nil
	}

	cred, err := GetStoredCredential()
	if err != nil || cred.Token == "" {
		return false
	}

	// Validate the stored token
	return c.ValidateToken(cred.Token) == nil
}

// Legacy function for backward compatibility
func IsAuthenticated() bool {
	client := NewAuthClient(DefaultAuthOpts())
	return client.IsAuthenticated()
}

// GetAuthenticatedUser returns the authenticated user's login
func GetAuthenticatedUser() (string, error) {
	cred, err := GetStoredCredential()
	if err != nil {
		return "", fmt.Errorf("not authenticated: %w", err)
	}

	// Return stored username if available
	if cred.Username != "" {
		return cred.Username, nil
	}

	// Fetch username from GitHub API if not stored
	username, err := getUsernameFromToken(cred.Token)
	if err != nil {
		return "", fmt.Errorf("failed to get user info: %w", err)
	}

	return username, nil
}

// ValidateToken checks if the provided token is valid
func (c *AuthClient) ValidateToken(token string) error {
	if token == "" {
		return fmt.Errorf("no authentication token provided")
	}

	// Create HTTP client with the token
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.%s/user", c.opts.GitHubHost), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("User-Agent", "dragonglass-cli")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to validate token: %w", err)
	}
	defer func() {
		_ = resp.Body.Close() // Ignore error on close
	}()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("token is invalid or expired")
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response: %d", resp.StatusCode)
	}

	return nil
}

// Legacy function for backward compatibility
func ValidateToken(hostname, token string) error {
	opts := DefaultAuthOpts().WithHost(hostname)
	client := NewAuthClient(opts)
	return client.ValidateToken(token)
}

// RequireAuth ensures the user is authenticated, prompting if needed
func RequireAuth() error {
	if IsAuthenticated() {
		return nil
	}

	fmt.Printf("🔐 Authentication required to access GitHub Container Registry\n")
	fmt.Printf("📦 Dragonglass needs permission to read packages from ghcr.io\n\n")
	fmt.Printf("Please run: dragonglass auth\n\n")

	return fmt.Errorf("not authenticated - please run 'dragonglass auth' first")
}

// GetToken retrieves authentication token (respects token override)
func (c *AuthClient) GetToken() (string, error) {
	// Return override token if provided
	if c.opts.Token != "" {
		if err := c.ValidateToken(c.opts.Token); err != nil {
			return "", fmt.Errorf("provided token is invalid: %w", err)
		}
		return c.opts.Token, nil
	}

	cred, err := GetStoredCredential()
	if err != nil {
		return "", fmt.Errorf("no stored credentials found: %w", err)
	}

	if cred.Token == "" {
		return "", fmt.Errorf("no authentication token found")
	}

	// Validate token before returning
	if err := c.ValidateToken(cred.Token); err != nil {
		// Clear invalid stored token
		_ = ClearStoredToken()
		return "", fmt.Errorf("stored token is invalid: %w", err)
	}

	return cred.Token, nil
}

// Legacy function for backward compatibility
func GetToken() (string, error) {
	client := NewAuthClient(DefaultAuthOpts())
	return client.GetToken()
}

// GetHTTPClient returns an authenticated HTTP client for GitHub API calls
func (c *AuthClient) GetHTTPClient() (*http.Client, error) {
	token, err := c.GetToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get authentication token: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}

	// Return a transport that adds auth headers
	originalTransport := client.Transport
	if originalTransport == nil {
		originalTransport = http.DefaultTransport
	}

	client.Transport = &authenticatedTransport{
		token:     token,
		transport: originalTransport,
	}

	return client, nil
}

// GetHTTPClient returns an authenticated HTTP client for GitHub API calls (legacy)
func GetHTTPClient() (*http.Client, error) {
	client := NewAuthClient(DefaultAuthOpts())
	return client.GetHTTPClient()
}

// authenticatedTransport adds GitHub authentication headers
type authenticatedTransport struct {
	token     string
	transport http.RoundTripper
}

func (t *authenticatedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone request to avoid modifying original
	authReq := req.Clone(req.Context())
	authReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t.token))
	authReq.Header.Set("User-Agent", "dragonglass-cli")

	return t.transport.RoundTrip(authReq)
}

// Authenticate performs the complete authentication flow using device flow
func Authenticate() error {
	fmt.Printf("🚀 Starting dragonglass authentication...\n\n")

	// Run device flow authentication
	tokenResp, err := RunDeviceFlow(DefaultRequiredScopes)
	if err != nil {
		return fmt.Errorf("device flow authentication failed: %w", err)
	}

	// Get username for storage
	username, err := getUsernameFromToken(tokenResp.AccessToken)
	if err != nil {
		// Don't fail auth if we can't get username, just use empty string
		username = ""
	}

	// Store the credentials securely
	if err := StoreToken(tokenResp.AccessToken, tokenResp.Scope, username); err != nil {
		return fmt.Errorf("failed to store authentication token: %w", err)
	}

	fmt.Printf("🎉 Authentication complete! You can now access GitHub Container Registry.\n")
	return nil
}

// getUsernameFromToken extracts username from GitHub token
func getUsernameFromToken(token string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("User-Agent", "dragonglass-cli")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() {
		_ = resp.Body.Close() // Ignore error on close
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API error: %d", resp.StatusCode)
	}

	var user struct {
		Login string `json:"login"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", fmt.Errorf("failed to parse user response: %w", err)
	}

	return user.Login, nil
}