# Dragonglass CLI - Claude Development Guide

## Team Identities
- **Developer**: CrazyScissors (Claude)
- **Consul**: G-Doggeronius Maximus (Developer)

## CRITICAL: Commit Message Guidelines

- **NEVER include Co-Authored-By or any attribution in commit messages**
- **NEVER include "Generated with Claude Code" or similar attribution**
- Keep commit messages clean and professional
- Follow conventional commit format (feat:, fix:, docs:, etc.)
- Focus only on describing the actual changes made

## Code Style Guidelines

### No Emoji Policy
- **NEVER use emoji characters in output, messages, or code comments**
- Use clear, descriptive text instead of visual indicators
- Focus on professional, clean terminal output
- Examples:
  - Bad: `fmt.Printf("🔍 Verifying plugin...")`
  - Good: `fmt.Printf("Verifying plugin...")`

## Project Overview

**Dragonglass CLI** is a secure Obsidian plugin manager implementing supply chain security through:
- SLSA provenance verification
- SBOM attestation validation
- OCI registry distribution (ghcr.io)
- GitHub OAuth authentication

## Repository Structure

```
dragonglass-cli/
├── cmd/dragonglass/           # Main CLI entry point
├── internal/                  # Private packages
│   ├── auth/                 # GitHub device flow auth
│   ├── cmd/                  # Command implementations
│   │   ├── auth/            # Authentication commands
│   │   ├── install/         # Plugin installation
│   │   ├── list/            # Plugin listing
│   │   └── verify/          # Attestation verification
│   ├── config/              # Configuration management
│   ├── lockfile/            # Plugin lockfile handling
│   ├── plugin/              # Plugin metadata parsing
│   └── registry/            # OCI registry client
├── pkg/                      # Public packages (if needed)
├── bin/                      # Built binaries
└── documentation/            # Specs, plans, README
```

## Build System (Makefile)

### Essential Commands
```bash
# Development
make build                    # Standard build
make dev                     # Development build with debug symbols
make install                 # Install to GOPATH/bin

# Testing & Quality
make test                    # Run all tests
make test-coverage           # Generate coverage report
make fmt                     # Format code
make lint                    # Run golangci-lint

# Environment-specific builds
make build-dev               # dev.obsidian.plugin annotation prefix
make build-test             # test.obsidian.plugin annotation prefix
make build ANNOTATION_PREFIX=custom.obsidian.plugin

# Cross-platform
make build-all              # Build for Darwin + Linux (amd64/arm64)

# Cleanup
make clean                  # Remove build artifacts
```

### Build Configuration
- **Binary**: `dragonglass`
- **Go Version**: 1.25.0
- **Annotation Prefix**: Configurable namespace for plugin metadata
- **LDFLAGS**: Version, commit, build time injection

## Technology Stack

### Core Dependencies
- **CLI Framework**: `github.com/spf13/cobra` v1.10.1
- **OCI Registry**: `oras.land/oras-go/v2` v2.6.0
- **GitHub Auth**: `github.com/cli/go-gh` v1.2.1
- **Image Spec**: `github.com/opencontainers/image-spec` v1.1.1

### Key Packages
- **Container Standards**: OpenContainers Go digest, image-spec
- **Authentication**: go-gh for GitHub device flow OAuth
- **Registry Operations**: ORAS v2 for OCI artifact handling
- **Credential Storage**: Cross-platform keychain via go-keyring

## CLI Commands & Usage

### Authentication
```bash
dragonglass auth            # Start GitHub device flow
dragonglass auth status     # Check auth status
dragonglass auth logout     # Clear credentials
```

### Plugin Management
```bash
dragonglass install ghcr.io/owner/repo:tag    # Install verified plugin
dragonglass verify ghcr.io/owner/repo:tag     # Verify without installing
dragonglass list                               # List installed plugins
```

## Configuration

### Per-Vault Config (`.obsidian/dragonglass-config.json`)
```json
{
  "version": "1.0",
  "defaultRegistry": "ghcr.io",
  "outputFormat": "table",
  "verificationMode": "warn",
  "autoUpdate": false
}
```

### Plugin Lockfile (`.obsidian/dragonglass-lock.json`)
```json
{
  "version": "1.0",
  "plugins": {
    "plugin-id": {
      "name": "Plugin Name",
      "version": "1.0.0",
      "ociReference": "ghcr.io/owner/plugin:1.0.0",
      "digest": "sha256:abc123...",
      "installedAt": "2024-01-15T10:30:00Z",
      "verificationStatus": "verified",
      "lastVerified": "2024-01-15T10:30:00Z"
    }
  }
}
```

## Plugin Metadata Format

Uses configurable annotation namespace (default: `vnd.obsidian.plugin`):

```json
{
  "vnd.obsidian.plugin.id": "plugin-id",
  "vnd.obsidian.plugin.name": "Plugin Name",
  "vnd.obsidian.plugin.version": "1.0.0",
  "vnd.obsidian.plugin.minAppVersion": "0.15.0",
  "vnd.obsidian.plugin.description": "Plugin description",
  "vnd.obsidian.plugin.author": "Author Name",
  "vnd.obsidian.plugin.authorUrl": "https://github.com/author/plugin",
  "vnd.obsidian.plugin.isDesktopOnly": "false"
}
```

## Security Attestations

### Provenance (SLSA)
- **Media Type**: `application/vnd.in-toto+json`
- **Predicate Type**: `https://slsa.dev/provenance/v1`
- **Format**: DSSE envelope with SLSA provenance attestation

### SBOM (SPDX)
- **Media Type**: `application/vnd.in-toto+json`
- **Predicate Type**: `https://spdx.dev/Document/v2.3`
- **Format**: DSSE envelope with SPDX SBOM attestation

## Development Status

### ✅ Implemented
- Project bootstrap with Cobra CLI framework
- Configuration management (per-vault)
- Lockfile management (plugin tracking)
- GitHub OAuth device flow authentication
- Secure credential storage (keychain + file fallback)
- OCI registry client (ORAS-authenticated)
- Plugin metadata parsing (configurable annotations)

### 🔄 In Progress
- Plugin file extraction from OCI layers
- SLSA provenance verification (DSSE parsing)
- SBOM analysis (SPDX/CycloneDX processing)
- Vulnerability scanning (CVE integration)
- Plugin installation (file extraction to `.obsidian/plugins/`)

## Development Workflow

### Code Standards
- All Go files start with 2-line ABOUTME comments
- Follow existing code style and conventions
- Use real implementations (no mock mode)
- Maintain test coverage for all functionality

### Testing Strategy
- **Unit Tests**: Each component in isolation
- **Integration Tests**: End-to-end workflows
- **Coverage Reports**: `make test-coverage`
- **Linting**: `golangci-lint` via `make lint`

### Git Workflow
- Use JJ if configured, otherwise Git
- Conventional commit format
- Imperative mood, present tense
- NEVER use `--no-verify` on commits

## Authentication Flow

### GitHub Device Flow Steps
1. CLI requests device code from GitHub
2. User visits verification URL and enters code
3. CLI polls for access token
4. Token stored in OS keychain (with file fallback)
5. Token used for ORAS registry authentication

### Storage Hierarchy
1. **Primary**: OS keychain (secure)
2. **Fallback**: File-based storage
3. **Cross-platform**: macOS, Linux, Windows support

## Important Notes

- **No Mock Mode**: Always use real APIs and data
- **Security First**: All plugins must pass provenance verification
- **OCI Native**: Plugin distribution via container registries
- **Per-Vault**: Configuration scoped to individual Obsidian vaults
- **Build-time Config**: Annotation prefixes configurable at compile time

---

*Ave, CrazyScissors reporting for duty! Ready to secure the plugin supply chain, Consul G-Doggeronius Maximus!*