# Dragonglass CLI Specification

## Overview

Dragonglass is a secure Obsidian plugin manager that performs verification of provenance and SBOM attestations with vulnerability scanning. It mitigates supply chain attacks and enables continuous verification of plugins through a controlled ecosystem hosted in OCI registries.

## Problem Statement

The current Obsidian plugin ecosystem lacks:
- Supply chain security verification
- Continuous vulnerability scanning
- Provenance attestation for plugin origins
- Software Bill of Materials (SBOM) transparency

Dragonglass addresses these security concerns by establishing a verified plugin distribution channel.

## Architecture

### Core Components
- **CLI Tool**: Go-based command-line interface for macOS and Linux
- **OCI Registry**: GitHub Container Registry (ghcr.io) for artifact storage
- **Verification Pipeline**: Integrated SLSA provenance, SPDX SBOM, and vulnerability scanning
- **GitHub App**: OAuth device flow for authentication

### Plugin Sources
- Plugins must be built using the standardized workflow: `gillisandrew/dragonglass-poc/.github/workflows/build.yml`
- Only plugins from this controlled ecosystem are supported (no community plugin imports)

## Technical Specifications

### Authentication
- **Method**: GitHub App with OAuth device flow
- **Credential Storage**: Native OS credential store (preferred) or `~/.dragonglass/credentials`
- **Caching**: Authentication tokens cached between CLI invocations

### OCI Artifact Structure
- **Plugin Files**: Located at root of OCI image
- **Metadata**: Obsidian plugin manifest information stored as OCI manifest annotations
- **Attestations**: SLSA provenance and SBOM stored as separate OCI artifacts with standard media types in DSSE format
  - **Provenance**: `application/vnd.in-toto+json` media type with SLSA provenance attestation
    - **Predicate Type**: `https://slsa.dev/provenance/v1`
  - **SBOM**: `application/vnd.in-toto+json` media type with SPDX SBOM attestation
    - **Predicate Type**: `https://spdx.dev/Document/v2.3`
  - **Format**: Dead Simple Signing Envelope (DSSE) with in-toto attestation payloads

### Verification Standards
- **Provenance**: SLSA attestations
- **SBOM**: SPDX format
- **Vulnerability Scanning**: Standard vulnerability exchange format with CVE database links

### Installation Target
- **Directory**: `.obsidian/plugins/` (standard Obsidian plugin directory)
- **Integration**: Direct replacement/alongside community plugins

### State Management
- **Lockfile**: Per-vault lockfile (`.obsidian/dragonglass-lock.json`)
- **Contents**: Image hashes, OCI digest references, plugin metadata, verification timestamps
- **Configuration**: Per-vault config file for user preferences

## CLI Commands (MVP)

```bash
# Authentication
dragonglass auth

# Install verified plugin
dragonglass install ghcr.io/owner/repo:tag

# Verify without installing
dragonglass verify ghcr.io/owner/repo:tag

# List installed verified plugins
dragonglass list
```

## Verification Flow

1. **Download**: Pull OCI artifact from ghcr.io using GitHub App authentication
2. **Attestation Discovery**: Query registry for attestation artifacts using media type filters
3. **DSSE Verification**: Verify DSSE envelope signatures and extract attestation payloads
4. **Provenance Check**: Verify SLSA attestation against expected workflow and repository
5. **SBOM Analysis**: Parse SPDX/CycloneDX document for dependency inventory
6. **Vulnerability Scan**: Check for CVEs in dependencies using attestation data
7. **User Interaction**: Present findings with warning/acknowledgment prompt
8. **Installation**: Extract plugin files to `.obsidian/plugins/` on user approval

## Security Policies

### Verification Behavior
- **Failed Verification**: Warn user and prompt for acknowledgment
- **Vulnerabilities**: Warn and request acknowledgment unless plugin package itself is the main CVE subject
- **Missing Attestations**: Block installation with detailed error message

### Error Details
- **Vulnerability Warnings**: Include CVE links, severity levels, affected components
- **Verification Failures**: Include links to source repository for investigation
- **Structured Output**: Support for machine-readable error details

## Out of Scope (MVP)

- Plugin updates (`dragonglass update` command)
- Security policy configuration (strict/permissive modes)
- Artifact caching (beyond authentication tokens)
- Windows platform support
- Community plugin import/wrapping
- Plugin discovery/browsing interface

## Future Considerations

- Configurable security policies
- Plugin update workflows with semantic versioning
- Additional platform support
- Integration with Obsidian's plugin management UI
- Plugin discovery and search capabilities

## Platform Support

- **Initial**: macOS and Linux
- **Language**: Go (for excellent OCI registry support and cross-platform builds)
- **Distribution**: Native binaries for each supported platform

## Dependencies

- Go OCI registry client libraries
- GitHub API client for device flow authentication
- SLSA verification libraries
- SPDX parsing libraries
- OS-native credential store integration