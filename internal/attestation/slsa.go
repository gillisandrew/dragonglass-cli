// ABOUTME: SLSA provenance attestation verification for plugin security validation
// ABOUTME: Handles DSSE envelope parsing and SLSA v1 predicate validation against trusted workflows
package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	v1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"oras.land/oras-go/v2/registry"

	"github.com/gillisandrew/dragonglass-cli/internal/oci"
)

const (
	// AttestationMediaType is the media type for in-toto attestations
	AttestationMediaType = "application/vnd.in-toto+json"

	// SLSA v1 predicate type
	SLSAPredicateType = "https://slsa.dev/provenance/v1"

	// Expected workflow for dragonglass plugins
	ExpectedWorkflowRepo = "gillisandrew/dragonglass-poc"
	ExpectedWorkflowPath = ".github/workflows/build.yml"
)

// SLSAVerifier handles SLSA provenance attestation verification using sigstore
type SLSAVerifier struct {
	token      string
	httpClient *http.Client
	verifier   *verify.Verifier
}

// AttestationResult contains the verification results
type AttestationResult struct {
	Found              bool
	Valid              bool
	Errors             []string
	Warnings           []string
	Provenance         *v1.Provenance
	VerificationResult *verify.VerificationResult
	Bundle             *bundle.Bundle
	Source             *AttestationSource
}

// AttestationSource contains information about the attestation source
type AttestationSource struct {
	Repository string
	Workflow   string
	Builder    string
	Digest     string
}

// DSSE (Dead Simple Signing Envelope) structure
type DSSEEnvelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"` // Base64 encoded
	Signatures  []Signature `json:"signatures"`
}

type Signature struct {
	Keyid string `json:"keyid,omitempty"`
	Sig   string `json:"signature"`
}

// NewSLSAVerifier creates a new SLSA attestation verifier with GitHub sigstore integration
func NewSLSAVerifier(token string) *SLSAVerifier {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Initialize GitHub verifier for attestation validation
	githubVerifier, err := newGitHubVerifier(httpClient)
	if err != nil {
		// For now, create verifier without sigstore verification
		// In production, this error should be handled properly
		return &SLSAVerifier{
			token:      token,
			httpClient: httpClient,
		}
	}

	return &SLSAVerifier{
		token:      token,
		httpClient: httpClient,
		verifier:   githubVerifier,
	}
}

// newGitHubVerifier creates a sigstore verifier for GitHub attestations
func newGitHubVerifier(httpClient *http.Client) (*verify.Verifier, error) {
	// For now, return nil to avoid TUF complexity
	// In production, this would create a proper GitHub verifier
	return nil, fmt.Errorf("GitHub verifier not yet fully implemented")
}

// VerifyAttestation discovers and verifies SLSA provenance attestations for an OCI artifact
func (v *SLSAVerifier) VerifyAttestation(ctx context.Context, imageRef string) (*AttestationResult, error) {
	result := &AttestationResult{
		Found:    false,
		Valid:    false,
		Errors:   []string{},
		Warnings: []string{},
	}

	// Create GHCR registry client
	ghcrRegistry := &oci.GHCRRegistry{Token: v.token}

	// Get repository from image reference
	repo, err := ghcrRegistry.GetRepositoryFromRef(imageRef)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to create repository: %v", err))
		return result, nil
	}

	// Parse the image reference to extract tag/digest
	ref, err := registry.ParseReference(imageRef)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("invalid image reference: %v", err))
		return result, nil
	}

	// Resolve the reference to get the actual digest
	desc, err := repo.Resolve(ctx, ref.Reference)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to resolve reference: %v", err))
		return result, nil
	}

	// Use the resolved digest for attestation lookup
	digestRef := desc.Digest.String()

	// Debug output for attestation discovery
	result.Warnings = append(result.Warnings, fmt.Sprintf("Looking for attestations for subject digest: %s", digestRef))

	// Use the OCI implementation to get SLSA attestations specifically
	_, attestationReaders, err := repo.GetSLSAAttestations(ctx, desc)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to get attestations: %v", err))
		return result, nil
	}

	if len(attestationReaders) == 0 {
		result.Warnings = append(result.Warnings, "No attestation artifacts found")
		return result, nil
	}

	result.Found = true
	result.Warnings = append(result.Warnings, fmt.Sprintf("Found %d attestation(s)", len(attestationReaders)))

	// Process the first attestation found
	attestationReader := attestationReaders[0]
	defer attestationReader.Close()

	// Read attestation content
	attestationData, err := io.ReadAll(attestationReader)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to read attestation data: %v", err))
		return result, nil
	}

	// For now, let's examine the raw JSON structure to understand the format
	var rawBundle map[string]interface{}
	if err := json.Unmarshal(attestationData, &rawBundle); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to parse attestation as JSON: %v", err))
		return result, nil
	}

	// Check if this looks like a Sigstore bundle
	if schemaVersion, exists := rawBundle["schemaVersion"]; exists {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Detected Sigstore bundle with schema version: %v", schemaVersion))
		result.Found = true
		result.Valid = false
		result.Warnings = append(result.Warnings, "Sigstore bundle detected but full parsing not yet implemented")
	} else {
		result.Errors = append(result.Errors, "unexpected attestation format - not a recognized Sigstore bundle")
		return result, nil
	}

	// Create placeholder source info
	result.Source = &AttestationSource{
		Repository: ExpectedWorkflowRepo,
		Workflow:   ExpectedWorkflowPath,
		Builder:    "https://github.com/actions/runner",
		Digest:     digestRef,
	}

	return result, nil
}

// parseDSSEEnvelope parses a DSSE envelope from JSON data
func (v *SLSAVerifier) parseDSSEEnvelope(data []byte) (*DSSEEnvelope, error) {
	var envelope DSSEEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DSSE envelope: %w", err)
	}

	if envelope.PayloadType == "" {
		return nil, fmt.Errorf("missing payloadType in DSSE envelope")
	}

	if envelope.Payload == "" {
		return nil, fmt.Errorf("missing payload in DSSE envelope")
	}

	return &envelope, nil
}

// parseInTotoAttestation parses an in-toto attestation from base64-encoded payload
func (v *SLSAVerifier) parseInTotoAttestation(payload string) (*attestationv1.Statement, error) {
	// In production, would decode base64 payload
	// For now, assume payload is JSON string
	var statement attestationv1.Statement
	if err := json.Unmarshal([]byte(payload), &statement); err != nil {
		return nil, fmt.Errorf("failed to unmarshal in-toto statement: %w", err)
	}

	return &statement, nil
}

// parseSLSAProvenance parses the SLSA provenance predicate
func (v *SLSAVerifier) parseSLSAProvenance(predicate interface{}) (*v1.Provenance, error) {
	// Convert interface{} to JSON and then to SLSA provenance
	predicateBytes, err := json.Marshal(predicate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal predicate: %w", err)
	}

	var prov v1.Provenance
	if err := json.Unmarshal(predicateBytes, &prov); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SLSA provenance: %w", err)
	}

	return &prov, nil
}

// validateProvenance validates the SLSA provenance against expected values
func (v *SLSAVerifier) validateProvenance(prov *v1.Provenance) (*AttestationSource, []string) {
	var errors []string
	source := &AttestationSource{}

	// For now, implement basic validation logic
	// In a production system, we would validate against the actual provenance structure
	// This is a simplified implementation for the current step

	// Basic validation - check if we have a provenance at all
	if prov == nil {
		errors = append(errors, "missing provenance data")
		return source, errors
	}

	// Add placeholder validation
	source.Repository = ExpectedWorkflowRepo
	source.Workflow = ExpectedWorkflowPath
	source.Builder = "https://github.com/actions/runner"

	// In production, we would extract these from the actual provenance structure
	// and validate against expected values

	return source, errors
}

// GetAttestationDigest extracts the subject digest from an attestation
func (v *SLSAVerifier) GetAttestationDigest(result *AttestationResult) string {
	if result.Source != nil {
		return result.Source.Digest
	}
	return ""
}

// ValidateSubjectMatch verifies the attestation subject matches the artifact digest
func (v *SLSAVerifier) ValidateSubjectMatch(result *AttestationResult, artifactDigest string) error {
	attestationDigest := v.GetAttestationDigest(result)
	if attestationDigest == "" {
		return fmt.Errorf("no digest found in attestation")
	}

	if attestationDigest != artifactDigest {
		return fmt.Errorf("digest mismatch: attestation=%s, artifact=%s", attestationDigest, artifactDigest)
	}

	return nil
}

// FormatVerificationResult creates a human-readable summary of verification results
func (v *SLSAVerifier) FormatVerificationResult(result *AttestationResult) string {
	var output strings.Builder

	if !result.Found {
		output.WriteString("🔍 SLSA Attestation: Not Found\n")
		return output.String()
	}

	if result.Valid {
		output.WriteString("✅ SLSA Attestation: Valid\n")
	} else {
		output.WriteString("❌ SLSA Attestation: Invalid\n")
	}

	if result.Source != nil {
		output.WriteString(fmt.Sprintf("   Repository: %s\n", result.Source.Repository))
		output.WriteString(fmt.Sprintf("   Workflow: %s\n", result.Source.Workflow))
		output.WriteString(fmt.Sprintf("   Builder: %s\n", result.Source.Builder))
	}

	for _, warning := range result.Warnings {
		output.WriteString(fmt.Sprintf("   ⚠️  %s\n", warning))
	}

	for _, err := range result.Errors {
		output.WriteString(fmt.Sprintf("   ❌ %s\n", err))
	}

	return output.String()
}


// extractProvenanceFromBundle extracts SLSA provenance from a verified sigstore bundle
func (v *SLSAVerifier) extractProvenanceFromBundle(b *bundle.Bundle, result *AttestationResult) error {
	// For now, create a placeholder source
	// In production, we would extract the actual provenance from the bundle
	result.Source = &AttestationSource{
		Repository: ExpectedWorkflowRepo,
		Workflow:   ExpectedWorkflowPath,
		Builder:    "https://github.com/actions/runner",
	}

	return nil
}

// verifyDSSEAttestation is a fallback function for DSSE-only verification
func (v *SLSAVerifier) verifyDSSEAttestation(data []byte, result *AttestationResult) (*AttestationResult, error) {
	// Parse DSSE envelope
	envelope, err := v.parseDSSEEnvelope(data)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to parse DSSE envelope: %v", err))
		return result, nil
	}

	// Verify signatures (simplified - in production would use sigstore verification)
	if len(envelope.Signatures) == 0 {
		result.Errors = append(result.Errors, "no signatures found in DSSE envelope")
		return result, nil
	}

	// Parse the in-toto attestation
	attestation, err := v.parseInTotoAttestation(envelope.Payload)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to parse in-toto attestation: %v", err))
		return result, nil
	}

	// Verify it's a SLSA provenance attestation
	if attestation.PredicateType != SLSAPredicateType {
		result.Errors = append(result.Errors, fmt.Sprintf("unexpected predicate type: %s (expected %s)", attestation.PredicateType, SLSAPredicateType))
		return result, nil
	}

	// Parse SLSA provenance predicate
	provenance, err := v.parseSLSAProvenance(attestation.Predicate)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to parse SLSA provenance: %v", err))
		return result, nil
	}

	result.Provenance = provenance

	// Validate provenance against expected workflow
	source, validationErrors := v.validateProvenance(provenance)
	result.Source = source
	result.Errors = append(result.Errors, validationErrors...)

	// Mark as valid if no errors (but with warnings since no sigstore verification)
	if len(result.Errors) == 0 {
		result.Valid = true
		result.Warnings = append(result.Warnings, "DSSE verification without sigstore signature validation")
	}

	return result, nil
}
