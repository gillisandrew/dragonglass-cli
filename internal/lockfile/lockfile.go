// ABOUTME: Lockfile management for tracking installed verified plugins
// ABOUTME: Handles per-vault lockfiles with plugin metadata and verification state
package lockfile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	LockfileName       = "dragonglass-lock.json"
	LockfileVersion    = "1"
	DefaultLockfilePerms = 0644
)

// LockfileOpts configures how lockfiles are loaded and managed
type LockfileOpts struct {
	// Override lockfile path (default: auto-discover)
	LockfilePath string

	// Whether to create default lockfile if none exists
	CreateIfMissing bool

	// Override obsidian directory for auto-discovery
	ObsidianDir string

	// Custom vault path for new lockfiles
	VaultPath string
}

// DefaultLockfileOpts returns default lockfile loading options
func DefaultLockfileOpts() *LockfileOpts {
	return &LockfileOpts{
		CreateIfMissing: true,
	}
}

// WithLockfilePath sets a custom lockfile path
func (opts *LockfileOpts) WithLockfilePath(path string) *LockfileOpts {
	opts.LockfilePath = path
	return opts
}

// WithObsidianDir sets a custom obsidian directory for auto-discovery
func (opts *LockfileOpts) WithObsidianDir(dir string) *LockfileOpts {
	opts.ObsidianDir = dir
	return opts
}

// WithVaultPath sets a custom vault path for new lockfiles
func (opts *LockfileOpts) WithVaultPath(path string) *LockfileOpts {
	opts.VaultPath = path
	return opts
}

// WithCreateIfMissing controls whether to create default lockfile when missing
func (opts *LockfileOpts) WithCreateIfMissing(create bool) *LockfileOpts {
	opts.CreateIfMissing = create
	return opts
}

// LockfileManager handles lockfile loading and management
type LockfileManager struct {
	opts *LockfileOpts
}

// NewLockfileManager creates a lockfile manager with the given options
func NewLockfileManager(opts *LockfileOpts) *LockfileManager {
	if opts == nil {
		opts = DefaultLockfileOpts()
	}
	return &LockfileManager{opts: opts}
}

type Lockfile struct {
	Version     string                     `json:"version"`
	GeneratedAt time.Time                  `json:"generated_at"`
	UpdatedAt   time.Time                  `json:"updated_at"`
	Plugins     map[string]PluginEntry     `json:"plugins"`
	Metadata    LockfileMetadata           `json:"metadata"`
}

type PluginEntry struct {
	Name            string                 `json:"name"`
	Version         string                 `json:"version"`
	OCIReference    string                 `json:"oci_reference"`
	OCIDigest       string                 `json:"oci_digest"`
	VerificationState VerificationState    `json:"verification_state"`
	Metadata        PluginMetadata         `json:"metadata"`
}

type VerificationState struct {
	ProvenanceVerified bool     `json:"provenance_verified"`
	SBOMVerified      bool     `json:"sbom_verified"`
	VulnScanPassed    bool     `json:"vuln_scan_passed"`
	Warnings          []string `json:"warnings,omitempty"`
	Errors            []string `json:"errors,omitempty"`
}

type PluginMetadata struct {
	Author      string            `json:"author,omitempty"`
	Description string            `json:"description,omitempty"`
	Homepage    string            `json:"homepage,omitempty"`
	Repository  string            `json:"repository,omitempty"`
	License     string            `json:"license,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`
}

type LockfileMetadata struct {
	VaultPath        string `json:"vault_path"`
	DragongrassVersion string `json:"dragonglass_version"`
	SchemaVersion    string `json:"schema_version"`
}

func NewLockfile(vaultPath string) *Lockfile {
	now := time.Now().UTC()
	return &Lockfile{
		Version:     LockfileVersion,
		GeneratedAt: now,
		UpdatedAt:   now,
		Plugins:     make(map[string]PluginEntry),
		Metadata: LockfileMetadata{
			VaultPath:         vaultPath,
			DragongrassVersion: "dev", // TODO: get from build info
			SchemaVersion:     LockfileVersion,
		},
	}
}

func (l *Lockfile) Validate() error {
	if l.Version == "" {
		return fmt.Errorf("lockfile version is required")
	}

	if l.Plugins == nil {
		return fmt.Errorf("plugins map cannot be nil")
	}

	for pluginID, plugin := range l.Plugins {
		if plugin.Name == "" {
			return fmt.Errorf("plugin %s: name is required", pluginID)
		}
		if plugin.OCIReference == "" {
			return fmt.Errorf("plugin %s: OCI reference is required", pluginID)
		}
		if plugin.OCIDigest == "" {
			return fmt.Errorf("plugin %s: OCI digest is required", pluginID)
		}
	}

	return nil
}

func (l *Lockfile) AddPlugin(pluginID string, plugin PluginEntry) error {
	if pluginID == "" {
		return fmt.Errorf("plugin ID is required")
	}
	if plugin.Name == "" {
		return fmt.Errorf("plugin name is required")
	}

	l.Plugins[pluginID] = plugin
	l.UpdatedAt = time.Now().UTC()

	return nil
}

func (l *Lockfile) RemovePlugin(pluginID string) error {
	if _, exists := l.Plugins[pluginID]; !exists {
		return fmt.Errorf("plugin %s not found in lockfile", pluginID)
	}

	delete(l.Plugins, pluginID)
	l.UpdatedAt = time.Now().UTC()

	return nil
}

func (l *Lockfile) UpdatePluginVerification(pluginID string, verification VerificationState) error {
	plugin, exists := l.Plugins[pluginID]
	if !exists {
		return fmt.Errorf("plugin %s not found in lockfile", pluginID)
	}

	plugin.VerificationState = verification
	l.Plugins[pluginID] = plugin
	l.UpdatedAt = time.Now().UTC()

	return nil
}

func (l *Lockfile) GetPlugin(pluginID string) (PluginEntry, bool) {
	plugin, exists := l.Plugins[pluginID]
	return plugin, exists
}

func (l *Lockfile) FindPluginByName(name string) *PluginEntry {
	for _, plugin := range l.Plugins {
		if plugin.Name == name {
			return &plugin
		}
	}
	return nil
}

func (l *Lockfile) ListPlugins() []PluginEntry {
	plugins := make([]PluginEntry, 0, len(l.Plugins))
	for _, plugin := range l.Plugins {
		plugins = append(plugins, plugin)
	}
	return plugins
}

func generatePluginID(name, ociReference string) string {
	data := fmt.Sprintf("%s@%s", name, ociReference)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

func GetLockfilePath(obsidianDir string) string {
	return filepath.Join(obsidianDir, LockfileName)
}

func LoadLockfile(lockfilePath string) (*Lockfile, error) {
	if _, err := os.Stat(lockfilePath); os.IsNotExist(err) {
		vaultPath := filepath.Dir(filepath.Dir(lockfilePath))
		return NewLockfile(vaultPath), nil
	}

	data, err := os.ReadFile(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read lockfile: %w", err)
	}

	var lockfile Lockfile
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("failed to parse lockfile: %w", err)
	}

	if err := lockfile.Validate(); err != nil {
		return nil, fmt.Errorf("invalid lockfile: %w", err)
	}

	return &lockfile, nil
}

func SaveLockfile(lockfile *Lockfile, lockfilePath string) error {
	if err := lockfile.Validate(); err != nil {
		return fmt.Errorf("invalid lockfile: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(lockfilePath), 0755); err != nil {
		return fmt.Errorf("failed to create lockfile directory: %w", err)
	}

	data, err := json.MarshalIndent(lockfile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal lockfile: %w", err)
	}

	if err := os.WriteFile(lockfilePath, data, DefaultLockfilePerms); err != nil {
		return fmt.Errorf("failed to write lockfile: %w", err)
	}

	return nil
}

// LoadLockfile loads lockfile using the configured options
func (lm *LockfileManager) LoadLockfile() (*Lockfile, string, error) {
	// Use explicit path if provided
	if lm.opts.LockfilePath != "" {
		lockfile, err := LoadLockfile(lm.opts.LockfilePath)
		if err != nil && !os.IsNotExist(err) {
			return nil, "", fmt.Errorf("failed to load lockfile from %s: %w", lm.opts.LockfilePath, err)
		}
		if err == nil {
			return lockfile, lm.opts.LockfilePath, nil
		}
		if !lm.opts.CreateIfMissing {
			return nil, "", fmt.Errorf("lockfile not found: %s", lm.opts.LockfilePath)
		}
		// Create default lockfile at the specified path
		vaultPath := lm.opts.VaultPath
		if vaultPath == "" {
			vaultPath = filepath.Dir(filepath.Dir(lm.opts.LockfilePath))
		}
		defaultLockfile := NewLockfile(vaultPath)
		if err := SaveLockfile(defaultLockfile, lm.opts.LockfilePath); err != nil {
			return nil, "", fmt.Errorf("failed to create default lockfile: %w", err)
		}
		return defaultLockfile, lm.opts.LockfilePath, nil
	}

	// Use provided obsidian directory
	if lm.opts.ObsidianDir == "" {
		return nil, "", fmt.Errorf("no lockfile path or obsidian directory provided")
	}

	lockfilePath := GetLockfilePath(lm.opts.ObsidianDir)
	lockfile, err := LoadLockfile(lockfilePath)
	if err != nil {
		if !os.IsNotExist(err) || !lm.opts.CreateIfMissing {
			return nil, "", fmt.Errorf("failed to load lockfile: %w", err)
		}
		// Create default lockfile in obsidian directory
		vaultPath := lm.opts.VaultPath
		if vaultPath == "" {
			vaultPath = filepath.Dir(lm.opts.ObsidianDir)
		}
		defaultLockfile := NewLockfile(vaultPath)
		if err := SaveLockfile(defaultLockfile, lockfilePath); err != nil {
			return nil, "", fmt.Errorf("failed to create default lockfile: %w", err)
		}
		return defaultLockfile, lockfilePath, nil
	}

	return lockfile, lockfilePath, nil
}

// Legacy function for backward compatibility
func LoadFromObsidianDirectory(obsidianDir string) (*Lockfile, string, error) {
	opts := DefaultLockfileOpts().WithObsidianDir(obsidianDir)
	manager := NewLockfileManager(opts)
	return manager.LoadLockfile()
}