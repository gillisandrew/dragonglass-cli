// ABOUTME: Unit tests for generic attestation verification supporting both SLSA and SBOM
// ABOUTME: Tests GitHub CLI integration and vulnerability analysis functionality
package attestation

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewAttestationVerifier(t *testing.T) {
	token := "test-token"
	trustedBuilder := "https://github.com/actions/runner"
	verifier, err := NewAttestationVerifier(token, trustedBuilder)

	if err != nil {
		t.Fatalf("NewAttestationVerifier failed: %v", err)
	}

	if verifier == nil {
		t.Fatal("NewAttestationVerifier returned nil")
	}

	if verifier.token != token {
		t.Errorf("Expected token %s, got %s", token, verifier.token)
	}

	if verifier.trustedBuilder != trustedBuilder {
		t.Errorf("Expected trustedBuilder %s, got %s", trustedBuilder, verifier.trustedBuilder)
	}
}

func TestVerifySLSA(t *testing.T) {
	verifier := &AttestationVerifier{
		token:          "test-token",
		trustedBuilder: "https://github.com/actions/runner",
	}

	tests := []struct {
		name         string
		attestations []AttestationData
		expectValid  bool
		expectBuilder string
		expectRepo   string
		expectError  bool
	}{
		{
			name: "valid trusted builder",
			attestations: []AttestationData{
				{
					PredicateType: SLSAPredicateV1,
					Predicate: map[string]interface{}{
						"buildDefinition": map[string]interface{}{
							"buildType": "https://github.com/gillisandrew/dragonglass-poc/actions/workflows/build.yml@refs/heads/main",
							"externalParameters": map[string]interface{}{
								"workflow": map[string]interface{}{
									"ref": "refs/heads/main",
									"repository": "github.com/owner/repo",
								},
							},
						},
						"runDetails": map[string]interface{}{
							"builder": map[string]interface{}{
								"id": "https://github.com/actions/runner",
							},
						},
					},
				},
			},
			expectValid:   true,
			expectBuilder: "https://github.com/actions/runner",
			expectRepo:    "github.com/owner/repo",
			expectError:   false,
		},
		{
			name: "untrusted builder",
			attestations: []AttestationData{
				{
					PredicateType: SLSAPredicateV1,
					Predicate: map[string]interface{}{
						"buildDefinition": map[string]interface{}{
							"buildType": "https://malicious.com/builder",
							"externalParameters": map[string]interface{}{
								"workflow": map[string]interface{}{
									"ref": "refs/heads/main",
									"repository": "malicious/repo",
								},
							},
						},
						"runDetails": map[string]interface{}{
							"builder": map[string]interface{}{
								"id": "https://malicious.com/builder",
							},
						},
					},
				},
			},
			expectValid:   false,
			expectBuilder: "https://malicious.com/builder",
			expectError:   false,
		},
		{
			name:         "no attestations",
			attestations: []AttestationData{},
			expectValid:  false,
			expectError:  false,
		},
		{
			name: "malformed predicate",
			attestations: []AttestationData{
				{
					PredicateType: SLSAPredicateV1,
					Predicate:     "not-a-map",
				},
			},
			expectValid: false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := verifier.verifySLSA(tt.attestations)

			if tt.expectError && err == nil {
				t.Error("Expected error, but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if result == nil {
				t.Fatal("Expected non-nil result")
			}

			if result.Valid != tt.expectValid {
				t.Errorf("Expected valid=%t, got %t", tt.expectValid, result.Valid)
			}

			if tt.expectBuilder != "" && result.Builder != tt.expectBuilder {
				t.Errorf("Expected builder %s, got %s", tt.expectBuilder, result.Builder)
			}

			if tt.expectRepo != "" && result.Repository != tt.expectRepo {
				t.Errorf("Expected repository %s, got %s", tt.expectRepo, result.Repository)
			}
		})
	}
}

func TestVerifySBOM(t *testing.T) {
	verifier := &AttestationVerifier{
		token: "test-token",
	}

	tests := []struct {
		name           string
		attestations   []AttestationData
		expectValid    bool
		expectFormat   string
		expectComponents int
		expectVulns    int
		expectError    bool
	}{
		{
			name: "valid SPDX 2.3 SBOM",
			attestations: []AttestationData{
				{
					PredicateType: SBOMPredicateV2,
					Predicate: map[string]interface{}{
						"packages": []interface{}{
							map[string]interface{}{
								"name":        "safe-lib",
								"versionInfo": "1.0.0",
							},
							map[string]interface{}{
								"name":        "another-lib",
								"versionInfo": "2.0.0",
							},
						},
					},
				},
			},
			expectValid:      true,
			expectFormat:     "SPDX-2.3",
			expectComponents: 2,
			expectVulns:      0,
			expectError:      false,
		},
		{
			name: "SBOM with vulnerable package",
			attestations: []AttestationData{
				{
					PredicateType: SBOMPredicateV2,
					Predicate: map[string]interface{}{
						"packages": []interface{}{
							map[string]interface{}{
								"name":        "vulnerable-lib-test",
								"versionInfo": "0.1.0",
							},
						},
					},
				},
			},
			expectValid:      true,
			expectFormat:     "SPDX-2.3",
			expectComponents: 1,
			expectVulns:      1,
			expectError:      false,
		},
		{
			name: "SPDX 3.0 SBOM",
			attestations: []AttestationData{
				{
					PredicateType: SBOMPredicateV3,
					Predicate: map[string]interface{}{
						"packages": []interface{}{
							map[string]interface{}{
								"name":        "test-lib",
								"versionInfo": "1.0.0",
							},
						},
					},
				},
			},
			expectValid:      true,
			expectFormat:     "SPDX-3.0",
			expectComponents: 1,
			expectVulns:      0,
			expectError:      false,
		},
		{
			name:         "no attestations",
			attestations: []AttestationData{},
			expectValid:  false,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := verifier.verifySBOM(tt.attestations)

			if tt.expectError && err == nil {
				t.Error("Expected error, but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if result == nil {
				t.Fatal("Expected non-nil result")
			}

			if result.Valid != tt.expectValid {
				t.Errorf("Expected valid=%t, got %t", tt.expectValid, result.Valid)
			}

			if tt.expectFormat != "" && result.Format != tt.expectFormat {
				t.Errorf("Expected format %s, got %s", tt.expectFormat, result.Format)
			}

			if tt.expectComponents > 0 && result.Components != tt.expectComponents {
				t.Errorf("Expected %d components, got %d", tt.expectComponents, result.Components)
			}

			if len(result.Vulnerabilities) != tt.expectVulns {
				t.Errorf("Expected %d vulnerabilities, got %d", tt.expectVulns, len(result.Vulnerabilities))
			}
		})
	}
}

func TestAnalyzeVulnerabilities(t *testing.T) {
	verifier := &AttestationVerifier{
		token: "test-token",
	}

	tests := []struct {
		name        string
		sbomData    map[string]interface{}
		expectVulns int
	}{
		{
			name: "safe packages only",
			sbomData: map[string]interface{}{
				"packages": []interface{}{
					map[string]interface{}{
						"name":        "safe-lib",
						"versionInfo": "1.0.0",
					},
					map[string]interface{}{
						"name":        "another-safe-lib",
						"versionInfo": "2.0.0",
					},
				},
			},
			expectVulns: 0,
		},
		{
			name: "one vulnerable package",
			sbomData: map[string]interface{}{
				"packages": []interface{}{
					map[string]interface{}{
						"name":        "vulnerable-lib-test",
						"versionInfo": "0.1.0",
					},
					map[string]interface{}{
						"name":        "safe-lib",
						"versionInfo": "1.0.0",
					},
				},
			},
			expectVulns: 1,
		},
		{
			name: "multiple vulnerable packages",
			sbomData: map[string]interface{}{
				"packages": []interface{}{
					map[string]interface{}{
						"name":        "vulnerable-lib-1",
						"versionInfo": "0.1.0",
					},
					map[string]interface{}{
						"name":        "vulnerable-lib-2",
						"versionInfo": "0.2.0",
					},
				},
			},
			expectVulns: 2,
		},
		{
			name:        "no packages",
			sbomData:    map[string]interface{}{},
			expectVulns: 0,
		},
		{
			name: "malformed packages",
			sbomData: map[string]interface{}{
				"packages": "not-an-array",
			},
			expectVulns: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulns := verifier.analyzeVulnerabilities(tt.sbomData)

			if len(vulns) != tt.expectVulns {
				t.Errorf("Expected %d vulnerabilities, got %d", tt.expectVulns, len(vulns))
			}

			// Validate vulnerability structure if any found
			for _, vuln := range vulns {
				if vuln.ID == "" {
					t.Error("Vulnerability missing ID")
				}
				if vuln.Severity == "" {
					t.Error("Vulnerability missing severity")
				}
				if vuln.Component == "" {
					t.Error("Vulnerability missing component")
				}
				if vuln.Description == "" {
					t.Error("Vulnerability missing description")
				}
			}
		})
	}
}

func TestNormalizeDigest(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "already prefixed",
			input:    "sha256:abc123def456",
			expected: "sha256:abc123def456",
		},
		{
			name:     "64 char hex without prefix",
			input:    "abc123def456789012345678901234567890abcdef1234567890123456789012",
			expected: "sha256:abc123def456789012345678901234567890abcdef1234567890123456789012",
		},
		{
			name:     "short hex without prefix",
			input:    "abc123",
			expected: "abc123",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeDigest(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestValidateSubjectMatch(t *testing.T) {
	verifier := &AttestationVerifier{
		token: "test-token",
	}

	tests := []struct {
		name           string
		result         *VerificationResult
		artifactDigest string
		expectError    bool
	}{
		{
			name: "matching digests with SLSA",
			result: &VerificationResult{
				SLSA: &SLSAResult{
					Digest: "sha256:abc123",
				},
				ArtifactDigest: "sha256:def456",
			},
			artifactDigest: "sha256:abc123",
			expectError:    false,
		},
		{
			name: "matching digests with artifact fallback",
			result: &VerificationResult{
				ArtifactDigest: "sha256:abc123",
			},
			artifactDigest: "sha256:abc123",
			expectError:    false,
		},
		{
			name: "mismatched digests",
			result: &VerificationResult{
				ArtifactDigest: "sha256:abc123",
			},
			artifactDigest: "sha256:def456",
			expectError:    true,
		},
		{
			name: "no digest in result",
			result: &VerificationResult{
				ArtifactDigest: "",
			},
			artifactDigest: "sha256:abc123",
			expectError:    true,
		},
		{
			name: "digest normalization",
			result: &VerificationResult{
				ArtifactDigest: "abc123def456789012345678901234567890abcdef1234567890123456789012",
			},
			artifactDigest: "sha256:abc123def456789012345678901234567890abcdef1234567890123456789012",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.ValidateSubjectMatch(tt.result, tt.artifactDigest)

			if tt.expectError && err == nil {
				t.Error("Expected error, but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestFormatVerificationResult(t *testing.T) {
	verifier := &AttestationVerifier{
		token: "test-token",
	}

	tests := []struct {
		name     string
		result   *VerificationResult
		contains []string
	}{
		{
			name: "not found",
			result: &VerificationResult{
				Found: false,
				Valid: false,
			},
			contains: []string{"Not Found"},
		},
		{
			name: "valid with SLSA and SBOM",
			result: &VerificationResult{
				Found: true,
				Valid: true,
				SLSA: &SLSAResult{
					Valid:      true,
					Repository: "gillisandrew/dragonglass-poc",
					Workflow:   ".github/workflows/build.yml",
					Builder:    "https://github.com/actions/runner",
				},
				SBOM: &SBOMResult{
					Valid:      true,
					Format:     "SPDX-2.3",
					Components: 42,
					Vulnerabilities: []Vulnerability{},
				},
			},
			contains: []string{
				"Attestations: Valid",
				"SLSA Provenance: Valid",
				"Repository: gillisandrew/dragonglass-poc",
				"SBOM: Valid",
				"Format: SPDX-2.3",
				"Components: 42",
				"No known vulnerabilities",
			},
		},
		{
			name: "invalid with vulnerabilities",
			result: &VerificationResult{
				Found: true,
				Valid: false,
				Errors: []string{"validation failed"},
				Warnings: []string{"minor issue"},
				SBOM: &SBOMResult{
					Valid:      true,
					Format:     "SPDX-2.3",
					Components: 10,
					Vulnerabilities: []Vulnerability{
						{
							ID:          "CVE-2024-TEST",
							Severity:    "HIGH",
							Component:   "test-lib",
							Version:     "1.0.0",
							Description: "Test vulnerability",
						},
					},
				},
			},
			contains: []string{
				"Attestations: Invalid",
				"Vulnerabilities: 1 found",
				"CVE-2024-TEST (HIGH)",
				"validation failed",
				"minor issue",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := verifier.FormatVerificationResult(tt.result)

			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("Output missing expected string '%s'\nOutput: %s", expected, output)
				}
			}
		})
	}
}

func TestVerifyAttestations_Integration(t *testing.T) {
	// This would be an integration test that requires actual registry access
	// For now, we'll create a mock test that simulates the flow

	verifier, err := NewAttestationVerifier("test-token", "https://github.com/actions/runner")
	if err != nil {
		t.Skipf("Skipping integration test due to verifier creation failure: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test with invalid image reference
	result, err := verifier.VerifyAttestations(ctx, "invalid-ref")
	if err != nil {
		t.Errorf("Expected no error for invalid ref (should return result with errors), got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Found {
		t.Error("Expected attestation not found for invalid reference")
	}

	if len(result.Errors) == 0 {
		t.Error("Expected errors for invalid reference")
	}
}