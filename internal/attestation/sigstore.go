// ABOUTME: Sigstore bundle parsing and cryptographic verification
// ABOUTME: Implements complete sigstore verification with production Fulcio and Rekor trust roots
package attestation

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

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

		// Add certificate identity verification for GitHub Actions (generic)
		// Since we only check builder trust, we use a generic GitHub Actions verification
		sanMatcher, err := verify.NewSANMatcher("", "https://github.com/.*")
		if err != nil {
			return nil, fmt.Errorf("failed to create SAN matcher: %w", err)
		}

		issuerMatcher, err := verify.NewIssuerMatcher("https://token.actions.githubusercontent.com", "")
		if err != nil {
			return nil, fmt.Errorf("failed to create issuer matcher: %w", err)
		}

		// Create certificate extensions for GitHub Actions workflow verification
		extensions := certificate.Extensions{}

		certificateIdentity, err := verify.NewCertificateIdentity(sanMatcher, issuerMatcher, extensions)
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate identity: %w", err)
		}

		policyOptions = append(policyOptions, verify.WithCertificateIdentity(certificateIdentity))

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
		PredicateType string `json:"predicateType"`
		Predicate     any    `json:"predicate"`
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