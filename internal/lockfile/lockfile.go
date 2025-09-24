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
	ImageHash       string                 `json:"image_hash"`
	InstallPath     string                 `json:"install_path"`
	InstallTime     time.Time              `json:"install_time"`
	LastVerified    time.Time              `json:"last_verified"`
	VerificationState VerificationState    `json:"verification_state"`
	Metadata        PluginMetadata         `json:"metadata"`
}

type VerificationState struct {
	ProvenanceVerified bool      `json:"provenance_verified"`
	SBOMVerified      bool      `json:"sbom_verified"`
	VulnScanPassed    bool      `json:"vuln_scan_passed"`
	VerificationTime  time.Time `json:"verification_time"`
	Warnings          []string  `json:"warnings,omitempty"`
	Errors            []string  `json:"errors,omitempty"`
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
		if plugin.InstallPath == "" {
			return fmt.Errorf("plugin %s: install path is required", pluginID)
		}
	}

	return nil
}

func (l *Lockfile) AddPlugin(plugin PluginEntry) error {
	if plugin.Name == "" {
		return fmt.Errorf("plugin name is required")
	}

	pluginID := generatePluginID(plugin.Name, plugin.OCIReference)
	plugin.InstallTime = time.Now().UTC()
	plugin.LastVerified = plugin.InstallTime

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
	plugin.LastVerified = time.Now().UTC()
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

func LoadFromObsidianDirectory(obsidianDir string) (*Lockfile, string, error) {
	lockfilePath := GetLockfilePath(obsidianDir)

	lockfile, err := LoadLockfile(lockfilePath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load lockfile: %w", err)
	}

	return lockfile, lockfilePath, nil
}