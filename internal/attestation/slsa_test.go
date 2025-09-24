// ABOUTME: Unit tests for SLSA provenance attestation verification functionality
// ABOUTME: Tests DSSE envelope parsing, in-toto attestation validation, and workflow verification
package attestation

import (
	"context"
	"strings"
	"testing"
	"time"

	v1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	"google.golang.org/protobuf/types/known/structpb"
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




func TestValidateProvenance(t *testing.T) {
	verifier := NewSLSAVerifier("test-token")

	tests := []struct {
		name           string
		provenance     *v1.Provenance
		expectedErrors int
		expectRepo     string
		expectWorkflow string
		expectBuilder  string
	}{
		{
			name: "valid GitHub Actions provenance",
			provenance: &v1.Provenance{
				BuildDefinition: &v1.BuildDefinition{
					BuildType: TrustedBuilder,
					ExternalParameters: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"repository": {Kind: &structpb.Value_StringValue{StringValue: "gillisandrew/dragonglass-poc"}},
							"workflow":   {Kind: &structpb.Value_StringValue{StringValue: ".github/workflows/build.yml"}},
						},
					},
				},
				RunDetails: &v1.RunDetails{
					Builder: &v1.Builder{
						Id: TrustedBuilder,
					},
					Metadata: &v1.BuildMetadata{
						InvocationId: "https://github.com/gillisandrew/dragonglass-poc/actions/runs/123",
					},
				},
			},
			expectedErrors: 0, // Now should work correctly with fixed parsing
			expectRepo:     "gillisandrew/dragonglass-poc", // Correctly extracted repository
			expectWorkflow: ".github/workflows/build.yml",
			expectBuilder:  TrustedBuilder,
		},
		{
			name: "untrusted builder",
			provenance: &v1.Provenance{
				BuildDefinition: &v1.BuildDefinition{
					BuildType: "https://malicious.com/builder",
					ExternalParameters: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"repository": {Kind: &structpb.Value_StringValue{StringValue: "malicious/repo"}},
						},
					},
				},
				RunDetails: &v1.RunDetails{
					Builder: &v1.Builder{
						Id: "https://malicious.com/builder",
					},
				},
			},
			expectedErrors: 1, // Should error on untrusted builder
			expectBuilder:  "https://malicious.com/builder",
		},
		{
			name: "missing run details",
			provenance: &v1.Provenance{
				BuildDefinition: &v1.BuildDefinition{
					BuildType: "https://github.com/actions/runner",
					ExternalParameters: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"repository": {Kind: &structpb.Value_StringValue{StringValue: "test/repo"}},
						},
					},
				},
				RunDetails: nil,
			},
			expectedErrors: 1, // Should error on missing run details
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

			if tt.expectBuilder != "" && source.Builder != tt.expectBuilder {
				t.Errorf("Expected builder %s, got %s", tt.expectBuilder, source.Builder)
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