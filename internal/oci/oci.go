package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
	defer func() {
		_ = rc.Close() // Ignore error on close
	}() // don't forget to close
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
					// This is a SLSA provenance attestation - we need to extract the bundle from the manifest's layer
					bundleReader, err := r.extractBundleFromManifest(ctx, referrer)
					if err != nil {
						return fmt.Errorf("failed to extract bundle from SLSA referrer %s: %w", referrer.Digest, err)
					}

					// Note: caller is responsible for closing the readers
					attestations = append(attestations, bundleReader)
				}
			}
		}
		return nil
	}); err != nil {
		return nil, nil, fmt.Errorf("failed to fetch referrers for %s: %w", subjectDesc.Digest, err)
	}
	return &subjectDesc, attestations, nil
}

// extractBundleFromManifest fetches the OCI manifest and extracts the Sigstore bundle from its layer
func (r *Repository) extractBundleFromManifest(ctx context.Context, manifestDesc ocispec.Descriptor) (io.ReadCloser, error) {
	// Fetch the manifest content
	manifestReader, err := r.Fetch(ctx, manifestDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer func() {
		_ = manifestReader.Close() // Ignore error on close
	}()

	// Read and parse the manifest
	manifestData, err := content.ReadAll(manifestReader, manifestDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	// Find the bundle layer (should be the first and only layer in attestation artifacts)
	if len(manifest.Layers) == 0 {
		return nil, fmt.Errorf("no layers found in attestation manifest")
	}

	bundleLayer := manifest.Layers[0]
	if bundleLayer.MediaType != "application/vnd.dev.sigstore.bundle.v0.3+json" {
		return nil, fmt.Errorf("unexpected layer media type: %s", bundleLayer.MediaType)
	}

	// Fetch the bundle layer content
	bundleReader, err := r.Fetch(ctx, bundleLayer)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bundle layer: %w", err)
	}

	return bundleReader, nil
}

// ExtractPluginFiles extracts main.js and styles.css from OCI layers to target directory
func (r *Repository) ExtractPluginFiles(ctx context.Context, manifest *ocispec.Manifest, targetDir string) error {
	// Create target directory if it doesn't exist
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	// Process each layer (expecting main.js and styles.css)
	for _, layer := range manifest.Layers {
		// Get filename from layer annotations
		filename, ok := layer.Annotations["org.opencontainers.image.title"]
		if !ok || filename == "" {
			continue // Skip layers without filename annotation
		}

		// Only process main.js and styles.css
		if filename != "main.js" && filename != "styles.css" {
			continue
		}

		// Fetch layer content
		layerReader, err := r.Fetch(ctx, layer)
		if err != nil {
			return fmt.Errorf("failed to fetch %s: %w", filename, err)
		}
		defer layerReader.Close()

		// Read layer content
		layerData, err := content.ReadAll(layerReader, layer)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", filename, err)
		}

		// Write file to target directory
		filePath := filepath.Join(targetDir, filename)
		if err := os.WriteFile(filePath, layerData, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", filename, err)
		}
	}

	return nil
}

// FileInfo represents information about a file in a layer
type FileInfo struct {
	Name string
	Size int64
	Mode uint32
}

// Fetch the content
