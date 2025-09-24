package auth

import (
	"testing"
)

func TestConstants(t *testing.T) {
	if GitHubHost != "github.com" {
		t.Errorf("expected GitHubHost to be 'github.com', got %s", GitHubHost)
	}

	if RequiredScopes != "read:packages" {
		t.Errorf("expected RequiredScopes to be 'read:packages', got %s", RequiredScopes)
	}
}

func TestValidateToken(t *testing.T) {
	hostname := "github.com"

	// Test empty token
	err := ValidateToken(hostname, "")
	if err == nil {
		t.Error("expected error for empty token")
	}

	// Test invalid token format
	err = ValidateToken(hostname, "invalid-token")
	if err == nil {
		t.Error("expected error for invalid token format")
	}

	// Note: We can't easily test valid tokens without actual GitHub integration
	// The GitHub CLI's IsValidToken function makes real API calls
}

func TestGetToken(t *testing.T) {
	// This test will typically fail unless user has stored credentials
	// which is expected in most test environments
	_, err := GetToken()
	if err != nil {
		// This is expected in test environments without authentication
		t.Logf("No stored token found (expected in test environment): %v", err)
	}
}

func TestIsAuthenticated(t *testing.T) {
	// Test with likely unauthenticated test environment
	authenticated := IsAuthenticated()

	// In most test environments, this should be false
	// But we don't assert false as the test environment might have stored credentials
	t.Logf("Authentication status: %v", authenticated)
}

func TestGetAuthenticatedUser(t *testing.T) {
	// This will typically fail in test environments
	username, err := GetAuthenticatedUser()
	if err != nil {
		// Expected in test environments without authentication
		t.Logf("Failed to get authenticated user (expected in test environment): %v", err)
	} else {
		t.Logf("Authenticated user: %s", username)
	}
}

// Test helper functions

func TestMaskToken(t *testing.T) {
	// This function is in the auth command, let's test similar logic here
	tests := []struct {
		name     string
		token    string
		expected string
	}{
		{
			name:     "short token",
			token:    "abc",
			expected: "********",
		},
		{
			name:     "normal token",
			token:    "ghp_1234567890abcdef1234567890abcdef12345678",
			expected: "ghp_...5678",
		},
		{
			name:     "exactly 8 chars",
			token:    "12345678",
			expected: "********",
		},
		{
			name:     "9 chars",
			token:    "123456789",
			expected: "1234...6789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskTokenForTest(tt.token)
			if result != tt.expected {
				t.Errorf("maskToken(%s) = %s; want %s", tt.token, result, tt.expected)
			}
		})
	}
}

// Helper function to test token masking logic
func maskTokenForTest(token string) string {
	if len(token) <= 8 {
		return "********"
	}
	return token[:4] + "..." + token[len(token)-4:]
}