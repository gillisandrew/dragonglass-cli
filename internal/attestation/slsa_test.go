// ABOUTME: Unit tests for SLSA provenance attestation verification functionality
// ABOUTME: Tests DSSE envelope parsing, in-toto attestation validation, and workflow verification
package attestation

import (
	"context"
	"strings"
	"testing"
	"time"

	v1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
)

func TestNewSLSAVerifier(t *testing.T) {
	token := "test-token"
	verifier := NewSLSAVerifier(token)

	if verifier == nil {
		t.Fatal("NewSLSAVerifier returned nil")
	}

	if verifier.token != token {
		t.Errorf("Expected token %s, got %s", token, verifier.token)
	}
}

func TestParseDSSEEnvelope(t *testing.T) {
	verifier := NewSLSAVerifier("test-token")

	tests := []struct {
		name        string
		input       string
		expectError bool
		expectedLen int
	}{
		{
			name: "valid DSSE envelope",
			input: `{
				"payloadType": "application/vnd.in-toto+json",
				"payload": "eyJ0ZXN0IjoicGF5bG9hZCJ9",
				"signatures": [
					{
						"keyid": "test-key",
						"signature": "test-signature"
					}
				]
			}`,
			expectError: false,
			expectedLen: 1,
		},
		{
			name: "missing payloadType",
			input: `{
				"payload": "eyJ0ZXN0IjoicGF5bG9hZCJ9",
				"signatures": []
			}`,
			expectError: true,
		},
		{
			name: "missing payload",
			input: `{
				"payloadType": "application/vnd.in-toto+json",
				"signatures": []
			}`,
			expectError: true,
		},
		{
			name:        "invalid JSON",
			input:       `{"invalid": json}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope, err := verifier.parseDSSEEnvelope([]byte(tt.input))

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error, but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if envelope == nil {
				t.Error("Expected non-nil envelope")
				return
			}

			if len(envelope.Signatures) != tt.expectedLen {
				t.Errorf("Expected %d signatures, got %d", tt.expectedLen, len(envelope.Signatures))
			}
		})
	}
}

func TestParseInTotoAttestation(t *testing.T) {
	verifier := NewSLSAVerifier("test-token")

	tests := []struct {
		name        string
		payload     string
		expectError bool
	}{
		{
			name: "valid in-toto statement",
			payload: `{
				"_type": "https://in-toto.io/Statement/v1",
				"subject": [
					{
						"name": "test-subject",
						"digest": {"sha256": "abc123"}
					}
				],
				"predicateType": "https://slsa.dev/provenance/v1",
				"predicate": {}
			}`,
			expectError: false,
		},
		{
			name:        "invalid JSON",
			payload:     `{"invalid": json}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statement, err := verifier.parseInTotoAttestation(tt.payload)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error, but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if statement == nil {
				t.Error("Expected non-nil statement")
			}
		})
	}
}

func TestParseSLSAProvenance(t *testing.T) {
	verifier := NewSLSAVerifier("test-token")

	tests := []struct {
		name        string
		predicate   interface{}
		expectError bool
	}{
		{
			name: "valid SLSA provenance",
			predicate: map[string]interface{}{
				"buildDefinition": map[string]interface{}{
					"buildType": "https://github.com/actions/runner",
					"externalParameters": map[string]interface{}{
						"repository": "gillisandrew/dragonglass-poc",
						"workflow":   ".github/workflows/build.yml",
					},
					"resolvedDependencies": []interface{}{
						map[string]interface{}{
							"uri": "git+https://github.com/gillisandrew/dragonglass-poc",
							"digest": map[string]interface{}{
								"sha1": "abc123",
							},
						},
					},
				},
				"runDetails": map[string]interface{}{
					"builder": map[string]interface{}{
						"id": "https://github.com/actions/runner",
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provenance, err := verifier.parseSLSAProvenance(tt.predicate)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error, but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if provenance == nil {
				t.Error("Expected non-nil provenance")
			}
		})
	}
}

func TestValidateProvenance(t *testing.T) {
	verifier := NewSLSAVerifier("test-token")

	tests := []struct {
		name           string
		provenance     *v1.Provenance
		expectedErrors int
		expectRepo     string
		expectWorkflow string
	}{
		{
			name:           "valid provenance",
			provenance:     &v1.Provenance{},
			expectedErrors: 0,
			expectRepo:     "gillisandrew/dragonglass-poc",
			expectWorkflow: ".github/workflows/build.yml",
		},
		{
			name:           "nil provenance",
			provenance:     nil,
			expectedErrors: 1, // Should error on nil provenance
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, errors := verifier.validateProvenance(tt.provenance)

			if len(errors) != tt.expectedErrors {
				t.Errorf("Expected %d errors, got %d: %v", tt.expectedErrors, len(errors), errors)
			}

			if tt.expectRepo != "" && source.Repository != tt.expectRepo {
				t.Errorf("Expected repository %s, got %s", tt.expectRepo, source.Repository)
			}

			if tt.expectWorkflow != "" && source.Workflow != tt.expectWorkflow {
				t.Errorf("Expected workflow %s, got %s", tt.expectWorkflow, source.Workflow)
			}
		})
	}
}

func TestFormatVerificationResult(t *testing.T) {
	verifier := NewSLSAVerifier("test-token")

	tests := []struct {
		name     string
		result   *AttestationResult
		contains []string
	}{
		{
			name: "not found",
			result: &AttestationResult{
				Found: false,
				Valid: false,
			},
			contains: []string{"Not Found"},
		},
		{
			name: "valid attestation",
			result: &AttestationResult{
				Found: true,
				Valid: true,
				Source: &AttestationSource{
					Repository: "gillisandrew/dragonglass-poc",
					Workflow:   ".github/workflows/build.yml",
					Builder:    "https://github.com/actions/runner",
				},
			},
			contains: []string{"Valid", "Repository:", "Workflow:", "Builder:"},
		},
		{
			name: "invalid attestation with errors",
			result: &AttestationResult{
				Found:  true,
				Valid:  false,
				Errors: []string{"validation failed", "signature invalid"},
				Source: &AttestationSource{
					Repository: "malicious/repo",
				},
			},
			contains: []string{"Invalid", "validation failed", "signature invalid"},
		},
		{
			name: "valid with warnings",
			result: &AttestationResult{
				Found:    true,
				Valid:    true,
				Warnings: []string{"minor issue detected"},
				Source: &AttestationSource{
					Repository: "gillisandrew/dragonglass-poc",
				},
			},
			contains: []string{"Valid", "minor issue detected"},
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

func TestValidateSubjectMatch(t *testing.T) {
	verifier := NewSLSAVerifier("test-token")

	tests := []struct {
		name           string
		result         *AttestationResult
		artifactDigest string
		expectError    bool
	}{
		{
			name: "matching digests",
			result: &AttestationResult{
				Source: &AttestationSource{
					Digest: "sha256:abc123",
				},
			},
			artifactDigest: "sha256:abc123",
			expectError:    false,
		},
		{
			name: "mismatched digests",
			result: &AttestationResult{
				Source: &AttestationSource{
					Digest: "sha256:abc123",
				},
			},
			artifactDigest: "sha256:def456",
			expectError:    true,
		},
		{
			name: "no attestation digest",
			result: &AttestationResult{
				Source: &AttestationSource{},
			},
			artifactDigest: "sha256:abc123",
			expectError:    true,
		},
		{
			name:           "no source",
			result:         &AttestationResult{},
			artifactDigest: "sha256:abc123",
			expectError:    true,
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

func TestVerifyAttestation_Integration(t *testing.T) {
	// This would be an integration test that requires actual registry access
	// For now, we'll create a mock test that simulates the flow

	verifier := NewSLSAVerifier("test-token")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test with invalid image reference
	result, err := verifier.VerifyAttestation(ctx, "invalid-ref")
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