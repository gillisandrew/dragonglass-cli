// ABOUTME: Result formatting and output utilities for attestation verification
// ABOUTME: Provides human-readable formatting of verification results and digest utilities
package attestation

import (
	"fmt"
	"strings"
)

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
		output.WriteString("Attestations: Not Found\n")
		return output.String()
	}

	if result.Valid {
		output.WriteString("Attestations: Valid\n")
	} else {
		output.WriteString("Attestations: Invalid\n")
	}

	// SLSA details
	if result.SLSA != nil {
		if result.SLSA.Valid {
			output.WriteString("SLSA Provenance: Valid\n")
		} else {
			output.WriteString("SLSA Provenance: Invalid\n")
		}
		output.WriteString(fmt.Sprintf("   Repository: %s\n", result.SLSA.Repository))
		output.WriteString(fmt.Sprintf("   Workflow: %s\n", result.SLSA.Workflow))
		output.WriteString(fmt.Sprintf("   Builder: %s\n", result.SLSA.Builder))
	}

	// SBOM details
	if result.SBOM != nil {
		if result.SBOM.Valid {
			output.WriteString("SBOM: Valid\n")
		} else {
			output.WriteString("SBOM: Invalid\n")
		}
		output.WriteString(fmt.Sprintf("   Format: %s\n", result.SBOM.Format))
		output.WriteString(fmt.Sprintf("   Components: %d\n", result.SBOM.Components))

		if len(result.SBOM.Vulnerabilities) > 0 {
			output.WriteString(fmt.Sprintf("   Vulnerabilities: %d found\n", len(result.SBOM.Vulnerabilities)))
			for _, vuln := range result.SBOM.Vulnerabilities {
				output.WriteString(fmt.Sprintf("     - %s (%s): %s in %s@%s\n",
					vuln.ID, vuln.Severity, vuln.Description, vuln.Component, vuln.Version))
			}
		} else {
			output.WriteString("   No known vulnerabilities\n")
		}
	}

	// Warnings and errors
	for _, warning := range result.Warnings {
		output.WriteString(fmt.Sprintf("   %s\n", warning))
	}

	for _, err := range result.Errors {
		output.WriteString(fmt.Sprintf("   %s\n", err))
	}

	return output.String()
}