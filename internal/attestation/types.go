// ABOUTME: Type definitions and constants for attestation verification system
// ABOUTME: Defines all core data structures for SLSA provenance and SBOM verification
package attestation

import (
	v1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
)

const (
	// Predicate types for different attestation formats
	SLSAPredicateV1 = "https://slsa.dev/provenance/v1"
	SBOMPredicateV2 = "https://spdx.dev/Document/v2.3"
	SBOMPredicateV3 = "https://spdx.dev/Document/v3.0"
)

// AttestationType represents the type of attestation
type AttestationType string

const (
	AttestationTypeSLSA AttestationType = "slsa"
	AttestationTypeSBOM AttestationType = "sbom"
)

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
	PredicateType string `json:"predicateType"`
	Predicate     any    `json:"predicate"`
}