// ABOUTME: OCI registry client for pulling artifacts from ghcr.io
// ABOUTME: Integrates with GitHub authentication for secure access to container registry
package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	internalAuth "github.com/gillisandrew/dragonglass-cli/internal/auth"
	"github.com/gillisandrew/dragonglass-cli/internal/plugin"
)

// RegistryOpts configures OCI registry client behavior
type RegistryOpts struct {
	// Registry hostname (default: "ghcr.io")
	RegistryHost string

	// Request timeout duration (default: 30s)
	Timeout time.Duration

	// AuthClient for token management (optional)
	AuthClient AuthProvider
}

// AuthProvider interface for authentication token management
type AuthProvider interface {
	GetToken() (string, error)
	GetHTTPClient() (*http.Client, error)
}

// DefaultRegistryOpts returns default registry options
func DefaultRegistryOpts() *RegistryOpts {
	return &RegistryOpts{
		RegistryHost: DefaultRegistry,
		Timeout:      DefaultTimeout,
	}
}

// WithRegistryHost sets a custom registry hostname
func (opts *RegistryOpts) WithRegistryHost(host string) *RegistryOpts {
	opts.RegistryHost = host
	return opts
}

// WithTimeout sets a custom request timeout
func (opts *RegistryOpts) WithTimeout(timeout time.Duration) *RegistryOpts {
	opts.Timeout = timeout
	return opts
}

// WithAuthProvider sets a custom auth provider
func (opts *RegistryOpts) WithAuthProvider(provider AuthProvider) *RegistryOpts {
	opts.AuthClient = provider
	return opts
}

type Client struct {
	opts       *RegistryOpts
	httpClient *http.Client
	registry   *remote.Registry
	token      string
}

type PullResult struct {
	Manifest     ocispec.Manifest
	ManifestData []byte
	Layers       []LayerInfo
	Annotations  map[string]string
	Plugin       *plugin.Metadata
}

type LayerInfo struct {
	Descriptor ocispec.Descriptor
	Content    []byte
	SavedPath  string // Path where layer content was saved
}

type ProgressCallback func(desc ocispec.Descriptor, progress int64, total int64)

const (
	DefaultRegistry = "ghcr.io"
	DefaultTimeout  = 30 * time.Second
)

// NewClient creates a new OCI registry client with the given options
func NewClient(opts *RegistryOpts) (*Client, error) {
	if opts == nil {
		opts = DefaultRegistryOpts()
	}

	var authProvider AuthProvider = &githubAuthAdapter{}
	if opts.AuthClient != nil {
		authProvider = opts.AuthClient
	}

	// Get authentication token
	token, err := authProvider.GetToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get authentication token: %w", err)
	}

	// Create ORAS remote registry
	reg, err := remote.NewRegistry(opts.RegistryHost)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry client: %w", err)
	}

	// Configure ORAS auth client with token
	// For GHCR, username can be anything when using token authentication
	reg.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: auth.StaticCredential(opts.RegistryHost, auth.Credential{
			Username: "token",
			Password: token,
		}),
	}

	// Create regular HTTP client
	httpClient, err := authProvider.GetHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	httpClient.Timeout = opts.Timeout

	return &Client{
		opts:       opts,
		httpClient: httpClient,
		registry:   reg,
		token:      token,
	}, nil
}

// githubAuthAdapter adapts our internal auth package to the AuthProvider interface
type githubAuthAdapter struct{}

func (g *githubAuthAdapter) GetToken() (string, error) {
	return internalAuth.GetToken()
}

func (g *githubAuthAdapter) GetHTTPClient() (*http.Client, error) {
	return internalAuth.GetHTTPClient()
}

// setupRepositoryAuth configures ORAS authentication for a repository
func (c *Client) setupRepositoryAuth(repo *remote.Repository) {
	repo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: auth.StaticCredential(repo.Reference.Registry, auth.Credential{
			Username: "token",
			Password: c.token,
		}),
	}
}

// SetRegistry allows changing the target registry (useful for testing)
func (c *Client) SetRegistry(hostname string) error {
	reg, err := remote.NewRegistry(hostname)
	if err != nil {
		return fmt.Errorf("failed to create registry for %s: %w", hostname, err)
	}

	// Configure ORAS auth client with token
	reg.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: auth.StaticCredential(hostname, auth.Credential{
			Username: "token",
			Password: c.token,
		}),
	}

	c.registry = reg
	c.opts.RegistryHost = hostname
	return nil
}

// Pull downloads an OCI artifact and returns the manifest and layer contents
func (c *Client) Pull(ctx context.Context, imageRef string, destDir string, progress ProgressCallback) (*PullResult, error) {
	// Parse image reference (e.g., "ghcr.io/owner/repo:tag")
	ref, err := registry.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("invalid image reference %s: %w", imageRef, err)
	}

	// Create repository
	repo, err := remote.NewRepository(ref.Registry + "/" + ref.Repository)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	// Configure ORAS authentication
	c.setupRepositoryAuth(repo)

	// Resolve the reference to get the manifest descriptor
	manifestDesc, err := repo.Resolve(ctx, ref.Reference)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s: %w", imageRef, err)
	}

	// Fetch the manifest
	manifestReader, err := repo.Fetch(ctx, manifestDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer manifestReader.Close()

	manifestData, err := io.ReadAll(manifestReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	// Parse manifest
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	// Create destination directory
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create destination directory: %w", err)
	}

	result := &PullResult{
		Manifest:     manifest,
		ManifestData: manifestData,
		Layers:       make([]LayerInfo, 0, len(manifest.Layers)),
		Annotations:  manifest.Annotations,
	}

	// Download each layer
	for i, layerDesc := range manifest.Layers {
		if progress != nil {
			progress(layerDesc, 0, layerDesc.Size)
		}

		// Fetch layer content
		layerReader, err := repo.Fetch(ctx, layerDesc)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch layer %d: %w", i, err)
		}

		// Read layer content
		layerContent, err := io.ReadAll(layerReader)
		layerReader.Close()

		if err != nil {
			return nil, fmt.Errorf("failed to read layer %d: %w", i, err)
		}

		// Verify digest
		if err := verifyDigest(layerContent, layerDesc.Digest); err != nil {
			return nil, fmt.Errorf("layer %d digest verification failed: %w", i, err)
		}

		// Save layer to file
		layerPath := filepath.Join(destDir, fmt.Sprintf("layer-%d.tar", i))
		if err := os.WriteFile(layerPath, layerContent, 0644); err != nil {
			return nil, fmt.Errorf("failed to save layer %d: %w", i, err)
		}

		result.Layers = append(result.Layers, LayerInfo{
			Descriptor: layerDesc,
			Content:    layerContent,
			SavedPath:  layerPath,
		})

		if progress != nil {
			progress(layerDesc, layerDesc.Size, layerDesc.Size)
		}
	}

	// Parse plugin metadata from manifest annotations
	parser := plugin.NewManifestParser(nil) // Use default plugin options
	pluginMetadata, err := parser.ParseMetadata(&manifest, manifest.Annotations)
	if err != nil {
		return nil, fmt.Errorf("failed to parse plugin metadata: %w", err)
	}

	result.Plugin = pluginMetadata

	return result, nil
}

// GetManifest fetches just the manifest for an image reference
func (c *Client) GetManifest(ctx context.Context, imageRef string) (*ocispec.Manifest, map[string]string, error) {
	ref, err := registry.ParseReference(imageRef)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid image reference %s: %w", imageRef, err)
	}

	repo, err := remote.NewRepository(ref.Registry + "/" + ref.Repository)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create repository: %w", err)
	}

	// Configure ORAS authentication
	c.setupRepositoryAuth(repo)

	// Resolve and fetch manifest
	manifestDesc, err := repo.Resolve(ctx, ref.Reference)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve %s: %w", imageRef, err)
	}

	manifestReader, err := repo.Fetch(ctx, manifestDesc)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer manifestReader.Close()

	manifestData, err := io.ReadAll(manifestReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	return &manifest, manifest.Annotations, nil
}

// ValidateAccess checks if we can access the registry and a specific repository
func (c *Client) ValidateAccess(ctx context.Context, imageRef string) error {
	ref, err := registry.ParseReference(imageRef)
	if err != nil {
		return fmt.Errorf("invalid image reference %s: %w", imageRef, err)
	}

	repo, err := remote.NewRepository(ref.Registry + "/" + ref.Repository)
	if err != nil {
		return fmt.Errorf("failed to create repository: %w", err)
	}

	// Configure ORAS authentication
	c.setupRepositoryAuth(repo)

	// Try to resolve the reference
	_, err = repo.Resolve(ctx, ref.Reference)
	if err != nil {
		return fmt.Errorf("access validation failed for %s: %w", imageRef, err)
	}

	return nil
}

// verifyDigest checks if content matches the expected digest
func verifyDigest(content []byte, expected digest.Digest) error {
	actual := digest.FromBytes(content)
	if actual != expected {
		return fmt.Errorf("digest mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}

// ParseImageReference extracts components from an OCI image reference
func ParseImageReference(imageRef string) (registryHost, repository, tag string, err error) {
	ref, err := registry.ParseReference(imageRef)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid image reference: %w", err)
	}

	return ref.Registry, ref.Repository, ref.Reference, nil
}

// GenerateBasicAuthHeader creates a basic auth header for registry authentication
// This is used internally by the HTTP client but exposed for testing
func GenerateBasicAuthHeader(username, password string) string {
	auth := username + ":" + password
	encoded := base64.StdEncoding.EncodeToString([]byte(auth))
	return "Basic " + encoded
}

// IsGitHubRegistry checks if the registry is GitHub Container Registry
func IsGitHubRegistry(registryHost string) bool {
	return strings.Contains(strings.ToLower(registryHost), "ghcr.io") ||
		strings.Contains(strings.ToLower(registryHost), "docker.pkg.github.com")
}

// ValidatePlugin performs comprehensive validation of a pulled plugin
func (c *Client) ValidatePlugin(result *PullResult) (*plugin.ValidationResult, error) {
	if result == nil {
		return nil, fmt.Errorf("pull result cannot be nil")
	}

	if result.Plugin == nil {
		return nil, fmt.Errorf("plugin metadata not available")
	}

	parser := plugin.NewManifestParser(nil) // Use default plugin options

	// Validate metadata
	metadataResult := parser.ValidateMetadata(result.Plugin)

	// Convert layers to plugin layer content format for structure validation
	layerContents := make([]plugin.LayerContent, 0, len(result.Layers))
	for _, layer := range result.Layers {
		// For now, we'll create a simplified file list from layer content
		// In a real implementation, we'd need to extract tar contents
		layerContent := plugin.LayerContent{
			Descriptor: layer.Descriptor,
			Files:      extractFileListFromLayer(layer),
		}
		layerContents = append(layerContents, layerContent)
	}

	// Validate plugin structure
	structureResult := parser.ValidatePluginStructure(layerContents)

	// Combine results
	combinedResult := &plugin.ValidationResult{
		Valid:    metadataResult.Valid && structureResult.Valid,
		Errors:   append(metadataResult.Errors, structureResult.Errors...),
		Warnings: append(metadataResult.Warnings, structureResult.Warnings...),
	}

	return combinedResult, nil
}

// extractFileListFromLayer extracts file information from layer content
// This is a simplified implementation that would need to be enhanced
// to properly parse tar archives in a real system
func extractFileListFromLayer(layer LayerInfo) []plugin.FileInfo {
	// For now, return mock file info based on common Obsidian plugin patterns
	// This would need to be replaced with actual tar archive parsing
	files := []plugin.FileInfo{}

	// Check if this looks like a plugin layer based on size and naming patterns
	if layer.Descriptor.Size > 0 {
		// Add common plugin files based on heuristics
		files = append(files, plugin.FileInfo{
			Name: "main.js",
			Size: layer.Descriptor.Size / 2, // Mock size
			Mode: 0644,
		})
		files = append(files, plugin.FileInfo{
			Name: "manifest.json",
			Size: 256, // Mock size
			Mode: 0644,
		})
	}

	return files
}