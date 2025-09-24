package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

type GHCRRegistry struct {
	Token string
}

func (r *GHCRRegistry) GetRepositoryFromRef(imageRef string) (*Repository, error) {
	// Parse image reference
	ref, err := registry.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference: %w", err)
	}
	// Create repository client
	repo, err := remote.NewRepository(ref.Registry + "/" + ref.Repository)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	// Configure authentication
	repo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: auth.StaticCredential(ref.Registry, auth.Credential{
			Username: "token",
			Password: r.Token,
		}),
	}
	return &Repository{repo}, nil
}

type Repository struct {
	*remote.Repository
}

func (r *Repository) FetchManifest(ctx context.Context, reference string) (*ocispec.Manifest, error) {

	descriptor, err := r.Resolve(ctx, reference)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve reference %s: %w", reference, err)
	}
	rc, err := r.Fetch(ctx, descriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch reference %s: %w", reference, err)
	}
	defer rc.Close() // don't forget to close
	pulledBlob, err := content.ReadAll(rc, descriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to read all content: %w", err)
	}

	manifest := &ocispec.Manifest{}
	err = json.Unmarshal(pulledBlob, manifest)

	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	return manifest, nil
}

func (r *Repository) GetSLSAAttestations(ctx context.Context, subjectDesc ocispec.Descriptor) (*ocispec.Descriptor, []io.ReadCloser, error) {
	attestations := []io.ReadCloser{}
	if err := r.Referrers(ctx, subjectDesc, "application/vnd.dev.sigstore.bundle.v0.3+json", func(referrers []ocispec.Descriptor) error {
		// for each page of the results, do the following:
		for _, referrer := range referrers {
			// Check if this referrer has the SLSA provenance predicate type annotation
			if predicateType, exists := referrer.Annotations["dev.sigstore.bundle.predicateType"]; exists {
				if predicateType == "https://slsa.dev/provenance/v1" {
					// This is a SLSA provenance attestation, fetch it
					rc, err := r.Fetch(ctx, referrer)
					if err != nil {
						return fmt.Errorf("failed to fetch SLSA referrer %s: %w", referrer.Digest, err)
					}

					// Note: caller is responsible for closing the readers
					attestations = append(attestations, rc)
				}
			}
		}
		return nil
	}); err != nil {
		return nil, nil, fmt.Errorf("failed to fetch referrers for %s: %w", subjectDesc.Digest, err)
	}
	return &subjectDesc, attestations, nil
}

// Fetch the content
