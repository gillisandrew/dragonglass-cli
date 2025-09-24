// ABOUTME: Main attestation verifier coordination and OCI discovery logic
// ABOUTME: Orchestrates multi-type attestation verification with SLSA provenance and SBOM attestations
package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"oras.land/oras-go/v2/registry"

	"github.com/gillisandrew/dragonglass-cli/internal/oci"
)

// AttestationVerifier handles verification of multiple attestation types using OCI attestation discovery
type AttestationVerifier struct {
	token          string
	httpClient     *http.Client
	verifier       *verify.Verifier
	trustedBuilder string
}

// NewAttestationVerifier creates a new attestation verifier with sigstore verification
func NewAttestationVerifier(token string, trustedBuilder string) (*AttestationVerifier, error) {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Initialize sigstore verifier with production trust roots
	sigstoreVerifier, err := newSigstoreVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to create sigstore verifier: %w", err)
	}

	return &AttestationVerifier{
		token:          token,
		httpClient:     httpClient,
		verifier:       sigstoreVerifier,
		trustedBuilder: trustedBuilder,
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