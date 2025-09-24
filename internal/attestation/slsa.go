// ABOUTME: SLSA provenance verification using in-toto attestation primitives
// ABOUTME: Validates SLSA provenance attestations and extracts build metadata
package attestation

import (
	"encoding/json"
	"fmt"
	"strings"

	v1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

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

			// Validate against trusted builder only
			if v.trustedBuilder != "" && result.Builder == v.trustedBuilder {
				result.Valid = true
			}
		}

		// Extract repository information from metadata for informational purposes
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

	// Extract repository from buildDefinition if not found in metadata (for testing/compatibility)
	if result.Repository == "" && result.Provenance != nil {
		buildDef := result.Provenance.GetBuildDefinition()
		if buildDef != nil {
			externalParams := buildDef.GetExternalParameters()
			if externalParams != nil {
				// Convert to map to access nested fields (needed for test compatibility)
				if paramsMap, ok := externalParams.AsMap()["workflow"]; ok {
					if workflowMap, ok := paramsMap.(map[string]any); ok {
						if repo, ok := workflowMap["repository"].(string); ok {
							result.Repository = repo
						}
					}
				}
			}
		}
	}

	return result, nil
}