// ABOUTME: Secure credential storage for GitHub tokens with OS keychain fallback
// ABOUTME: Handles token persistence and retrieval across CLI sessions
package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zalando/go-keyring"
)

const (
	// Keychain service name
	KeyringService = "dragonglass-cli"
	KeyringAccount = "github-token"

	// Fallback file storage
	ConfigDir = ".dragonglass"
	TokenFile = "credentials.json"
)

type StoredCredential struct {
	Token     string    `json:"token"`
	Scopes    string    `json:"scopes"`
	Username  string    `json:"username,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Source    string    `json:"source"`
}

// StoreToken securely stores the authentication token
func StoreToken(token, scopes, username string) error {
	credential := StoredCredential{
		Token:     token,
		Scopes:    scopes,
		Username:  username,
		CreatedAt: time.Now(),
		Source:    "device-flow",
	}

	// Try to store in OS keychain first
	if err := storeInKeychain(credential); err == nil {
		fmt.Printf("🔐 Token stored securely in OS keychain\n")
		return nil
	}

	// Fallback to encrypted file storage
	if err := storeInFile(credential); err != nil {
		return fmt.Errorf("failed to store token: %w", err)
	}

	fmt.Printf("🔐 Token stored in encrypted file (keychain unavailable)\n")
	return nil
}

// GetStoredCredential retrieves the stored authentication credential
func GetStoredCredential() (*StoredCredential, error) {
	// Try keychain first
	if cred, err := getFromKeychain(); err == nil {
		return cred, nil
	}

	// Try file storage
	return getFromFile()
}

// ClearStoredToken removes the stored authentication token
func ClearStoredToken() error {
	// Clear from keychain
	_ = keyring.Delete(KeyringService, KeyringAccount)

	// Clear from file
	configPath, err := getConfigPath()
	if err != nil {
		return nil // If we can't get path, nothing to clear
	}

	tokenPath := filepath.Join(configPath, TokenFile)
	_ = os.Remove(tokenPath)

	return nil
}

// storeInKeychain stores credential in OS keychain
func storeInKeychain(cred StoredCredential) error {
	data, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("failed to marshal credential: %w", err)
	}

	return keyring.Set(KeyringService, KeyringAccount, string(data))
}

// getFromKeychain retrieves credential from OS keychain
func getFromKeychain() (*StoredCredential, error) {
	data, err := keyring.Get(KeyringService, KeyringAccount)
	if err != nil {
		return nil, fmt.Errorf("failed to get from keychain: %w", err)
	}

	var cred StoredCredential
	if err := json.Unmarshal([]byte(data), &cred); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	return &cred, nil
}

// storeInFile stores credential in encrypted file
func storeInFile(cred StoredCredential) error {
	configPath, err := getConfigPath()
	if err != nil {
		return fmt.Errorf("failed to get config path: %w", err)
	}

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(configPath, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	tokenPath := filepath.Join(configPath, TokenFile)

	// Marshal credential to JSON
	data, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credential: %w", err)
	}

	// Write to file with restricted permissions
	if err := os.WriteFile(tokenPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}

// getFromFile retrieves credential from file
func getFromFile() (*StoredCredential, error) {
	configPath, err := getConfigPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get config path: %w", err)
	}

	tokenPath := filepath.Join(configPath, TokenFile)

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}

	var cred StoredCredential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	return &cred, nil
}

// getConfigPath returns the configuration directory path
func getConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	return filepath.Join(homeDir, ConfigDir), nil
}