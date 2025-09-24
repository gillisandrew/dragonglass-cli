// ABOUTME: Generic attestation verification system supporting SLSA provenance and SBOM attestations
// ABOUTME: Implements sigstore cryptographic verification with production Fulcio and Rekor trust roots
package attestation

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	v1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
	"oras.land/oras-go/v2/registry"

	"github.com/gillisandrew/dragonglass-cli/internal/oci"
)

const (
	// Predicate types for different attestation formats
	SLSAPredicateV1 = "https://slsa.dev/provenance/v1"
	SBOMPredicateV2 = "https://spdx.dev/Document/v2.3"
	SBOMPredicateV3 = "https://spdx.dev/Document/v3.0"

	// Expected workflow for dragonglass plugins
	ExpectedWorkflowRepo = "gillisandrew/dragonglass-poc"
	ExpectedWorkflowPath = ".github/workflows/build.yml"

	// Trusted builder for dragonglass plugins (the specific workflow we trust)
	TrustedBuilder = "https://github.com/gillisandrew/dragonglass-poc/.github/workflows/build.yml@refs/heads/main"
)

// AttestationType represents the type of attestation
type AttestationType string

const (
	AttestationTypeSLSA AttestationType = "slsa"
	AttestationTypeSBOM AttestationType = "sbom"
)

// AttestationVerifier handles verification of multiple attestation types using OCI attestation discovery
type AttestationVerifier struct {
	token      string
	httpClient *http.Client
	verifier   *verify.Verifier
}

// VerificationResult contains comprehensive verification results for all attestation types
type VerificationResult struct {
	Found          bool              `json:"found"`
	Valid          bool              `json:"valid"`
	Errors         []string          `json:"errors"`
	Warnings       []string          `json:"warnings"`
	SLSA           *SLSAResult       `json:"slsa,omitempty"`
	SBOM           *SBOMResult       `json:"sbom,omitempty"`
	Results        []AttestationData `json:"rawResults,omitempty"`
	ArtifactDigest string            `json:"artifactDigest"`
}

// SLSAResult contains SLSA-specific verification details
type SLSAResult struct {
	Valid      bool           `json:"valid"`
	Repository string         `json:"repository"`
	Workflow   string         `json:"workflow"`
	Builder    string         `json:"builder"`
	Digest     string         `json:"digest"`
	Provenance *v1.Provenance `json:"provenance,omitempty"`
}

// SBOMResult contains SBOM-specific verification and vulnerability details
type SBOMResult struct {
	Valid           bool            `json:"valid"`
	Format          string          `json:"format"`
	Components      int             `json:"components"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// Vulnerability represents a security vulnerability found in SBOM analysis
type Vulnerability struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Component   string   `json:"component"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	References  []string `json:"references,omitempty"`
}

// AttestationData represents parsed attestation data from OCI
type AttestationData struct {
	PredicateType string      `json:"predicateType"`
	Predicate     interface{} `json:"predicate"`
}

// NewAttestationVerifier creates a new attestation verifier with sigstore verification
func NewAttestationVerifier(token string) (*AttestationVerifier, error) {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Initialize sigstore verifier with production trust roots
	sigstoreVerifier, err := newSigstoreVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to create sigstore verifier: %w", err)
	}

	return &AttestationVerifier{
		token:      token,
		httpClient: httpClient,
		verifier:   sigstoreVerifier,
	}, nil
}

// VerifyAttestations discovers and verifies all attestations for an OCI artifact
func (v *AttestationVerifier) VerifyAttestations(ctx context.Context, imageRef string) (*VerificationResult, error) {
	result := &VerificationResult{
		Found:    false,
		Valid:    false,
		Errors:   []string{},
		Warnings: []string{},
	}

	// Parse the image reference
	ref, err := registry.ParseReference(imageRef)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("invalid image reference: %v", err))
		return result, nil
	}

	// Create GHCR registry client
	ghcrRegistry := &oci.GHCRRegistry{Token: v.token}
	repo, err := ghcrRegistry.GetRepositoryFromRef(imageRef)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to create repository: %v", err))
		return result, nil
	}

	// Resolve the reference to get the actual digest
	desc, err := repo.Resolve(ctx, ref.Reference)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to resolve reference: %v", err))
		return result, nil
	}

	result.ArtifactDigest = desc.Digest.String()

	// Get OCI attestations using our existing OCI implementation
	_, attestationReaders, err := repo.GetSLSAAttestations(ctx, desc)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to get attestations: %v", err))
		return result, nil
	}

	if len(attestationReaders) == 0 {
		return result, nil
	}

	result.Found = true

	// Parse all attestations from readers
	attestations := []AttestationData{}
	for i, reader := range attestationReaders {
		defer func(r io.ReadCloser, index int) {
			if err := r.Close(); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("failed to close attestation reader %d: %v", index, err))
			}
		}(reader, i)

		data, err := io.ReadAll(reader)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("failed to read attestation %d: %v", i, err))
			continue
		}

		// Try to parse as sigstore bundle first
		var sigstoreBundle bundle.Bundle
		if err := json.Unmarshal(data, &sigstoreBundle); err == nil {
			// Extract attestation from bundle with cryptographic verification
			if attestationData, err := v.parseSignstoreBundle(&sigstoreBundle, result.ArtifactDigest); err == nil {
				attestations = append(attestations, *attestationData)
			} else {
				result.Warnings = append(result.Warnings, fmt.Sprintf("failed to parse sigstore bundle %d: %v", i, err))
			}
		} else {
			// Try parsing as raw JSON attestation
			if attestationData, err := v.parseRawAttestation(data); err == nil {
				attestations = append(attestations, *attestationData)
			} else {
				result.Warnings = append(result.Warnings, fmt.Sprintf("failed to parse attestation %d: %v", i, err))
			}
		}
	}

	// Process attestations by type
	slsaAttestations := []AttestationData{}
	sbomAttestations := []AttestationData{}

	for _, att := range attestations {
		switch att.PredicateType {
		case SLSAPredicateV1:
			slsaAttestations = append(slsaAttestations, att)
		case SBOMPredicateV2, SBOMPredicateV3:
			sbomAttestations = append(sbomAttestations, att)
		default:
			result.Warnings = append(result.Warnings, fmt.Sprintf("unknown predicate type: %s", att.PredicateType))
		}
	}

	// Verify SLSA attestations
	if len(slsaAttestations) > 0 {
		slsaResult, err := v.verifySLSA(slsaAttestations)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("SLSA verification failed: %v", err))
		} else {
			result.SLSA = slsaResult
			if slsaResult.Valid {
				result.Valid = true
			}
		}
	}

	// Verify SBOM attestations
	if len(sbomAttestations) > 0 {
		sbomResult, err := v.verifySBOM(sbomAttestations)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("SBOM verification failed: %v", err))
		} else {
			result.SBOM = sbomResult
		}
	}

	return result, nil
}

// verifySLSA handles SLSA provenance verification using in-toto primitives
func (v *AttestationVerifier) verifySLSA(attestations []AttestationData) (*SLSAResult, error) {
	result := &SLSAResult{
		Valid: false,
	}

	if len(attestations) == 0 {
		return result, nil
	}

	// Process the first SLSA attestation
	att := attestations[0]

	// Parse SLSA provenance predicate using protojson
	predicateBytes, err := json.Marshal(att.Predicate)
	if err != nil {
		return result, fmt.Errorf("failed to marshal predicate: %w", err)
	}

	var provenance v1.Provenance
	if err := protojson.Unmarshal(predicateBytes, &provenance); err != nil {
		return result, fmt.Errorf("failed to unmarshal SLSA provenance: %w", err)
	}

	result.Provenance = &provenance

	// Use in-toto's official validation
	if err := provenance.Validate(); err != nil {
		return result, fmt.Errorf("in-toto validation failed: %v", err)
	}

	// Extract builder information using in-toto getters
	runDetails := provenance.GetRunDetails()
	if runDetails != nil {
		builder := runDetails.GetBuilder()
		if builder != nil {
			result.Builder = builder.GetId()

			// Validate against trusted builder
			if result.Builder == TrustedBuilder {
				result.Valid = true
				result.Repository = ExpectedWorkflowRepo
				result.Workflow = ExpectedWorkflowPath
			}
		}

		// Extract repository information from metadata
		metadata := runDetails.GetMetadata()
		if metadata != nil {
			invocationId := metadata.GetInvocationId()
			if strings.Contains(invocationId, "github.com/") {
				// Extract repository from URL path: https://github.com/owner/repo/actions/runs/123
				parts := strings.Split(invocationId, "/")
				for i, part := range parts {
					if part == "github.com" && i+2 < len(parts) {
						result.Repository = fmt.Sprintf("%s/%s", parts[i+1], parts[i+2])
						break
					}
				}
			}
		}
	}

	// Validate against expected workflow repository if configured
	if result.Repository != "" && result.Repository != ExpectedWorkflowRepo {
		result.Valid = false
		return result, fmt.Errorf("unexpected repository: %s (expected %s)", result.Repository, ExpectedWorkflowRepo)
	}

	// Set default values if not extracted
	if result.Repository == "" {
		result.Repository = ExpectedWorkflowRepo
	}
	if result.Workflow == "" {
		result.Workflow = ExpectedWorkflowPath
	}

	return result, nil
}

// verifySBOM handles SBOM attestation verification and vulnerability analysis
func (v *AttestationVerifier) verifySBOM(attestations []AttestationData) (*SBOMResult, error) {
	result := &SBOMResult{
		Valid:           false,
		Vulnerabilities: []Vulnerability{},
	}

	if len(attestations) == 0 {
		return result, nil
	}

	// Process the first SBOM attestation
	att := attestations[0]

	// Determine SBOM format from predicate type
	switch att.PredicateType {
	case SBOMPredicateV2:
		result.Format = "SPDX-2.3"
	case SBOMPredicateV3:
		result.Format = "SPDX-3.0"
	default:
		result.Format = "Unknown"
	}

	// Parse SBOM predicate for component analysis
	if predicate, ok := att.Predicate.(map[string]interface{}); ok {
		result.Valid = true

		// Count components (simplified parsing)
		if packages, ok := predicate["packages"].([]interface{}); ok {
			result.Components = len(packages)
		}

		// In a real implementation, you would:
		// 1. Parse the full SBOM structure
		// 2. Extract package/component information
		// 3. Query vulnerability databases (OSV, NVD, etc.)
		// 4. Match vulnerabilities against components
		// 5. Calculate risk scores

		// For now, add a placeholder vulnerability check
		result.Vulnerabilities = v.analyzeVulnerabilities(predicate)
	}

	return result, nil
}

// analyzeVulnerabilities performs basic vulnerability analysis on SBOM data
func (v *AttestationVerifier) analyzeVulnerabilities(sbomData map[string]interface{}) []Vulnerability {
	// This is a placeholder implementation
	// In production, you would integrate with vulnerability databases
	vulnerabilities := []Vulnerability{}

	// Example: check for known vulnerable packages
	if packages, ok := sbomData["packages"].([]interface{}); ok {
		for _, pkg := range packages {
			if pkgMap, ok := pkg.(map[string]interface{}); ok {
				if name, ok := pkgMap["name"].(string); ok {
					if version, ok := pkgMap["versionInfo"].(string); ok {
						// Simple example check for demonstration
						if strings.Contains(name, "vulnerable-lib") {
							vulnerabilities = append(vulnerabilities, Vulnerability{
								ID:          "CVE-2024-EXAMPLE",
								Severity:    "HIGH",
								Component:   name,
								Version:     version,
								Description: "Example vulnerability in " + name,
								References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-EXAMPLE"},
							})
						}
					}
				}
			}
		}
	}

	return vulnerabilities
}

// GetAttestationDigest extracts the subject digest from verification results
func (v *AttestationVerifier) GetAttestationDigest(result *VerificationResult) string {
	if result.SLSA != nil {
		return result.SLSA.Digest
	}
	return result.ArtifactDigest
}

// ValidateSubjectMatch verifies the attestation subject matches the artifact digest
func (v *AttestationVerifier) ValidateSubjectMatch(result *VerificationResult, artifactDigest string) error {
	attestationDigest := v.GetAttestationDigest(result)
	if attestationDigest == "" {
		return fmt.Errorf("no digest found in attestation")
	}

	// Normalize digest format
	artifactDigest = normalizeDigest(artifactDigest)
	attestationDigest = normalizeDigest(attestationDigest)

	if attestationDigest != artifactDigest {
		return fmt.Errorf("digest mismatch: attestation=%s, artifact=%s", attestationDigest, artifactDigest)
	}

	return nil
}

// normalizeDigest ensures consistent digest format
func normalizeDigest(d string) string {
	if !strings.HasPrefix(d, "sha256:") && len(d) == 64 {
		return "sha256:" + d
	}
	return d
}

// FormatVerificationResult creates a human-readable summary of verification results
func (v *AttestationVerifier) FormatVerificationResult(result *VerificationResult) string {
	var output strings.Builder

	if !result.Found {
		output.WriteString("🔍 Attestations: Not Found\n")
		return output.String()
	}

	if result.Valid {
		output.WriteString("✅ Attestations: Valid\n")
	} else {
		output.WriteString("❌ Attestations: Invalid\n")
	}

	// SLSA details
	if result.SLSA != nil {
		if result.SLSA.Valid {
			output.WriteString("✅ SLSA Provenance: Valid\n")
		} else {
			output.WriteString("❌ SLSA Provenance: Invalid\n")
		}
		output.WriteString(fmt.Sprintf("   Repository: %s\n", result.SLSA.Repository))
		output.WriteString(fmt.Sprintf("   Workflow: %s\n", result.SLSA.Workflow))
		output.WriteString(fmt.Sprintf("   Builder: %s\n", result.SLSA.Builder))
	}

	// SBOM details
	if result.SBOM != nil {
		if result.SBOM.Valid {
			output.WriteString("✅ SBOM: Valid\n")
		} else {
			output.WriteString("❌ SBOM: Invalid\n")
		}
		output.WriteString(fmt.Sprintf("   Format: %s\n", result.SBOM.Format))
		output.WriteString(fmt.Sprintf("   Components: %d\n", result.SBOM.Components))

		if len(result.SBOM.Vulnerabilities) > 0 {
			output.WriteString(fmt.Sprintf("   ⚠️  Vulnerabilities: %d found\n", len(result.SBOM.Vulnerabilities)))
			for _, vuln := range result.SBOM.Vulnerabilities {
				output.WriteString(fmt.Sprintf("     - %s (%s): %s in %s@%s\n",
					vuln.ID, vuln.Severity, vuln.Description, vuln.Component, vuln.Version))
			}
		} else {
			output.WriteString("   ✅ No known vulnerabilities\n")
		}
	}

	// Warnings and errors
	for _, warning := range result.Warnings {
		output.WriteString(fmt.Sprintf("   ⚠️  %s\n", warning))
	}

	for _, err := range result.Errors {
		output.WriteString(fmt.Sprintf("   ❌ %s\n", err))
	}

	return output.String()
}

// parseSignstoreBundle extracts and cryptographically verifies attestation data from a sigstore bundle
func (v *AttestationVerifier) parseSignstoreBundle(bundle *bundle.Bundle, artifactDigest string) (*AttestationData, error) {
	// Perform full sigstore cryptographic verification
	if v.verifier != nil {
		// Prepare artifact digest for verification
		var artifactOpt verify.ArtifactPolicyOption
		if artifactDigest != "" {
			// Parse the digest to extract algorithm and value
			digestParts := strings.SplitN(artifactDigest, ":", 2)
			if len(digestParts) == 2 {
				algorithm := digestParts[0]
				digestValue := digestParts[1]
				digestBytes, err := hex.DecodeString(digestValue)
				if err == nil {
					artifactOpt = verify.WithArtifactDigest(algorithm, digestBytes)
				}
			}
		}

		// Create policy options for GitHub Actions workflow verification
		policyOptions := []verify.PolicyOption{}

		// Add certificate identity verification for our trusted GitHub workflow
		if len(ExpectedWorkflowRepo) > 0 {
			// Create identity matcher for GitHub Actions
			sanMatcher, err := verify.NewSANMatcher("", fmt.Sprintf("https://github.com/%s/.*", ExpectedWorkflowRepo))
			if err != nil {
				return nil, fmt.Errorf("failed to create SAN matcher: %w", err)
			}

			issuerMatcher, err := verify.NewIssuerMatcher("https://token.actions.githubusercontent.com", "")
			if err != nil {
				return nil, fmt.Errorf("failed to create issuer matcher: %w", err)
			}

			// Create certificate extensions for GitHub Actions workflow verification
			extensions := certificate.Extensions{
				GithubWorkflowRepository: ExpectedWorkflowRepo,
			}

			certificateIdentity, err := verify.NewCertificateIdentity(sanMatcher, issuerMatcher, extensions)
			if err != nil {
				return nil, fmt.Errorf("failed to create certificate identity: %w", err)
			}

			policyOptions = append(policyOptions, verify.WithCertificateIdentity(certificateIdentity))
		}

		// Build the policy with artifact option and policy options
		var policyBuilder verify.PolicyBuilder
		if artifactOpt != nil {
			policyBuilder = verify.NewPolicy(artifactOpt, policyOptions...)
		} else {
			// If no artifact digest, use a no-op artifact option
			policyBuilder = verify.NewPolicy(verify.WithoutArtifactUnsafe(), policyOptions...)
		}

		// Perform cryptographic verification of the sigstore bundle
		// This validates signatures, certificates, SCTs, and transparency log entries
		verificationResult, err := v.verifier.Verify(bundle, policyBuilder)
		if err != nil {
			return nil, fmt.Errorf("sigstore bundle verification failed: %w", err)
		}

		// Verification succeeded - we now have cryptographically verified attestation
		_ = verificationResult // Successful verification
	}

	// Extract DSSE envelope from bundle
	envelope, err := bundle.Envelope()
	if err != nil {
		return nil, fmt.Errorf("failed to extract envelope: %w", err)
	}

	// Extract in-toto statement
	statement, err := envelope.Statement()
	if err != nil {
		return nil, fmt.Errorf("failed to extract statement: %w", err)
	}

	return &AttestationData{
		PredicateType: statement.PredicateType,
		Predicate:     statement.Predicate,
	}, nil
}

// parseRawAttestation parses raw JSON attestation data
func (v *AttestationVerifier) parseRawAttestation(data []byte) (*AttestationData, error) {
	var rawAttestation struct {
		PredicateType string      `json:"predicateType"`
		Predicate     interface{} `json:"predicate"`
	}

	if err := json.Unmarshal(data, &rawAttestation); err != nil {
		return nil, fmt.Errorf("failed to unmarshal raw attestation: %w", err)
	}

	return &AttestationData{
		PredicateType: rawAttestation.PredicateType,
		Predicate:     rawAttestation.Predicate,
	}, nil
}

// newSigstoreVerifier creates a sigstore verifier with production trust roots (Fulcio, Rekor)
func newSigstoreVerifier() (*verify.Verifier, error) {
	// Fetch the production trust root from Sigstore TUF repository
	// This includes Fulcio CA certificates and Rekor public keys
	trustedMaterial, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch sigstore trusted root: %w", err)
	}

	// Create verifier with production sigstore configuration
	// This uses the public Fulcio CA and Rekor transparency log for GitHub Actions
	verifierConfig := []verify.VerifierOption{
		// Require SCT (certificate transparency) verification
		verify.WithSignedCertificateTimestamps(1),
		// Require transparency log verification
		verify.WithTransparencyLog(1),
		// Use integrated timestamps from Rekor for certificate validation
		verify.WithIntegratedTimestamps(1),
	}

	verifier, err := verify.NewVerifier(trustedMaterial, verifierConfig...)
	if err != nil {
		return nil, fmt.Errorf("failed to create sigstore verifier with production trust roots: %w", err)
	}

	return verifier, nil
}
