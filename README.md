# Dragonglass CLI

A secure Obsidian plugin manager that performs verification of provenance and SBOM attestations with vulnerability scanning.

## Overview

Dragonglass mitigates supply chain attacks and enables continuous verification of plugins through a controlled ecosystem hosted in OCI registries (GitHub Container Registry).

## Features

- **Supply Chain Security**: SLSA provenance and SPDX SBOM verification
- **OCI Registry Integration**: Secure plugin distribution via ghcr.io
- **GitHub Authentication**: Seamless integration with GitHub CLI credentials
- **Per-Vault Management**: Configuration and lockfile per Obsidian vault
- **Configurable Annotation Namespace**: Build-time configurable plugin metadata keys

## Installation

```bash
# Build from source
make build

# Build with custom annotation prefix
make build ANNOTATION_PREFIX=custom.obsidian.plugin

# Install to GOPATH/bin
make install
```

## Usage

```bash
# Authenticate with GitHub
dragonglass auth

# Install a verified plugin
dragonglass install ghcr.io/owner/repo:tag

# Verify without installing
dragonglass verify ghcr.io/owner/repo:tag

# List installed plugins
dragonglass list
```

## Architecture

### Components Implemented

- ✅ **Project Bootstrap**: Go CLI with Cobra framework
- ✅ **Configuration Management**: Per-vault config in `.obsidian/dragonglass-config.json`
- ✅ **Lockfile Management**: Plugin tracking in `.obsidian/dragonglass-lock.json`
- ✅ **GitHub Authentication**: OAuth device flow via go-gh library
- ✅ **OCI Registry Client**: Authenticated artifact pulling with oras-go
- ✅ **Plugin Metadata Parsing**: Configurable annotation namespace support

### Components In Progress

- 🔄 **Plugin File Extraction**: OCI layer extraction and validation
- 🔄 **SLSA Provenance Verification**: DSSE attestation parsing and validation
- 🔄 **SBOM Analysis**: SPDX/CycloneDX document processing
- 🔄 **Vulnerability Scanning**: CVE database integration
- 🔄 **Plugin Installation**: File extraction to `.obsidian/plugins/`

## Plugin Metadata Format

Plugin metadata is stored in OCI manifest annotations using a configurable namespace (default: `vnd.obsidian.plugin`):

```json
{
  "vnd.obsidian.plugin.id": "example-plugin",
  "vnd.obsidian.plugin.name": "Example Plugin",
  "vnd.obsidian.plugin.version": "1.0.0",
  "vnd.obsidian.plugin.minAppVersion": "0.15.0",
  "vnd.obsidian.plugin.description": "An example plugin",
  "vnd.obsidian.plugin.author": "Example Author",
  "vnd.obsidian.plugin.authorUrl": "https://github.com/example/example-plugin",
  "vnd.obsidian.plugin.isDesktopOnly": "false"
}
```

## Attestation Format

Security attestations are stored as separate OCI artifacts:

- **Provenance**: `application/vnd.in-toto+json` media type with DSSE envelope
- **SBOM**: `application/spdx+json` or `application/vnd.cyclonedx+json` media type with DSSE envelope

## Development

```bash
# Run tests
make test

# Run tests with coverage
make test-coverage

# Build for development
make dev

# Build for different environments
make build-dev    # Uses dev.obsidian.plugin prefix
make build-test   # Uses test.obsidian.plugin prefix

# Format and lint
make fmt
make lint

# Clean build artifacts
make clean
```

## Configuration

### Per-Vault Configuration (`.obsidian/dragonglass-config.json`)

```json
{
  "version": "1.0",
  "defaultRegistry": "ghcr.io",
  "outputFormat": "table",
  "verificationMode": "warn",
  "autoUpdate": false
}
```

### Lockfile Format (`.obsidian/dragonglass-lock.json`)

```json
{
  "version": "1.0",
  "plugins": {
    "example-plugin": {
      "name": "Example Plugin",
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

## License

[License information to be added]