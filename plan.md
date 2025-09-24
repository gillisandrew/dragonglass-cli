# Dragonglass CLI Development Plan

## Overview
This plan breaks down the development of the Dragonglass CLI into small, iterative steps that build upon each other. Each step is designed to be implementable safely while moving the project forward meaningfully.

## Development Strategy
- **Language**: Go (excellent OCI registry support)
- **Approach**: Incremental development with working CLI at each step
- **Testing**: Unit tests for each component, integration tests for workflows
- **Architecture**: Modular design with clear separation of concerns

## Phase 1: Foundation (Steps 1-3)

### Step 1: Project Bootstrap
**Goal**: Create a working Go project with basic CLI structure
**Deliverable**: `dragonglass --help` works and shows command structure
**Size**: Small - project setup with minimal complexity

### Step 2: Configuration Management
**Goal**: Implement per-vault configuration file handling
**Deliverable**: CLI can read/write config files in `.obsidian/` directories
**Size**: Small - file I/O with basic validation

### Step 3: Lockfile Management
**Goal**: Implement lockfile creation, reading, and updating
**Deliverable**: CLI can manage `.obsidian/dragonglass-lock.json` files
**Size**: Small - JSON marshaling with struct definitions

## Phase 2: Authentication (Steps 4-5)

### Step 4: GitHub App Authentication Structure
**Goal**: Implement GitHub App device flow authentication without credential storage
**Deliverable**: `dragonglass auth` completes device flow and gets token
**Size**: Medium - OAuth flow implementation

### Step 5: Credential Storage
**Goal**: Add secure credential caching with OS keychain fallback
**Deliverable**: Tokens persist between CLI invocations securely
**Size**: Small-Medium - keychain integration with fallback

## Phase 3: OCI Integration (Steps 6-8)

### Step 6: Basic OCI Registry Client
**Goal**: Implement OCI artifact pulling from ghcr.io with authentication
**Deliverable**: CLI can download OCI images and extract contents
**Size**: Medium - OCI client library integration

### Step 7: OCI Manifest Parsing
**Goal**: Extract Obsidian plugin metadata from OCI manifest annotations
**Deliverable**: CLI can read plugin info from image annotations
**Size**: Small - JSON parsing and validation

### Step 8: Plugin File Extraction
**Goal**: Extract plugin files from OCI image to temporary directory
**Deliverable**: Plugin files are extracted and validated as Obsidian plugin structure
**Size**: Small - file system operations with validation

## Phase 4: Verification Pipeline (Steps 9-12)

### Step 9: SLSA Provenance Verification
**Goal**: Implement SLSA attestation verification against expected workflow
**Deliverable**: CLI can verify provenance of OCI artifacts
**Size**: Medium - SLSA library integration and workflow validation

### Step 10: SPDX SBOM Parsing
**Goal**: Parse and analyze SPDX documents from OCI attestations
**Deliverable**: CLI can extract dependency information from SBOM
**Size**: Medium - SPDX parsing with dependency analysis

### Step 11: Vulnerability Scanning Integration
**Goal**: Check SBOM dependencies against vulnerability databases
**Deliverable**: CLI identifies CVEs in plugin dependencies with links
**Size**: Medium - vulnerability database integration

### Step 12: Verification Results Presentation
**Goal**: Present verification results with user prompts for acknowledgment
**Deliverable**: CLI shows detailed verification results and gets user consent
**Size**: Small-Medium - UI/UX for terminal interaction

## Phase 5: Plugin Management (Steps 13-15)

### Step 13: Plugin Installation
**Goal**: Install verified plugins to `.obsidian/plugins/` directory
**Deliverable**: `dragonglass install` command works end-to-end
**Size**: Small - file operations with conflict handling

### Step 14: List Installed Plugins
**Goal**: Implement plugin listing from lockfile and filesystem
**Deliverable**: `dragonglass list` shows installed verified plugins
**Size**: Small - data presentation from existing structures

### Step 15: Verify Without Installation
**Goal**: Implement verification-only mode
**Deliverable**: `dragonglass verify` shows verification results without installing
**Size**: Small - reuse existing verification pipeline

## Implementation Prompts

### Prompt 1: Project Bootstrap
```
Create a new Go CLI application called 'dragonglass' using Cobra for command structure. Set up the project with:

1. Go modules initialization (go.mod)
2. Basic project structure with cmd/, internal/, and pkg/ directories
3. Main CLI with subcommands: auth, install, verify, list
4. Each subcommand should have placeholder implementations that print their name
5. Include proper CLI help text and descriptions based on the specification
6. Add a Makefile for building the binary
7. Include basic error handling and logging setup

The CLI should follow Go best practices and have a clean, maintainable structure. Make sure `dragonglass --help` shows all available commands with descriptions.
```

### Prompt 2: Configuration Management
```
Implement configuration file management for the Dragonglass CLI. Build upon the existing CLI structure by adding:

1. A Config struct that represents user preferences (initially just basic settings)
2. Functions to read/write config files from `.obsidian/` directories
3. Config file location logic that searches up the directory tree for `.obsidian/`
4. Default configuration values and validation
5. Integration into the existing CLI commands to use configuration
6. Unit tests for configuration loading and saving

The configuration should be stored as JSON in `.obsidian/dragonglass-config.json` and include fields for future extensibility. Handle cases where the config file doesn't exist or is malformed gracefully.
```

### Prompt 3: Lockfile Management
```
Implement lockfile management building on the existing configuration system. Add:

1. A Lockfile struct with fields for plugin metadata, hashes, and verification timestamps
2. Functions to create, read, and update lockfiles in `.obsidian/dragonglass-lock.json`
3. Plugin entry structure with OCI digest, installation path, and metadata
4. Lockfile versioning for future compatibility
5. Integration with existing CLI commands to maintain lockfile state
6. Unit tests for lockfile operations including concurrent access scenarios

The lockfile should track installed plugins with enough information to verify and manage them later. Include proper JSON marshaling with omitempty tags for optional fields.
```

### Prompt 4: GitHub App Authentication Structure
```
Implement GitHub App device flow authentication. Extend the existing CLI by adding:

1. GitHub App configuration (app ID, client ID) as constants
2. Device flow OAuth implementation using GitHub's device flow API
3. Token response handling and validation
4. Integration with the 'auth' command to complete the flow
5. Basic token validation and refresh logic
6. Error handling for network failures and authentication errors
7. Unit tests for authentication flow (with mocked HTTP responses)

Do not implement credential storage yet - just handle the authentication flow and return tokens. The auth command should guide users through the device flow process with clear instructions.
```

### Prompt 5: Credential Storage
```
Add secure credential storage to the existing authentication system. Build upon the GitHub App authentication by adding:

1. OS keychain integration for macOS and Linux (using keyring library)
2. Fallback file-based storage in ~/.dragonglass/credentials with proper permissions
3. Token encryption for file-based storage
4. Integration with existing auth command to persist tokens
5. Token retrieval functions for use by other commands
6. Token invalidation and cleanup functionality
7. Unit tests for credential storage and retrieval across platforms

Update the authentication flow to automatically store tokens after successful authentication. Include proper error handling for keychain access failures.
```

### Prompt 6: Basic OCI Registry Client
```
Implement OCI registry client functionality. Build on existing authentication by adding:

1. OCI registry client using oras-go library
2. ghcr.io registry configuration and authentication integration
3. OCI artifact pulling with progress indication
4. Image manifest and layer downloading
5. Basic artifact verification (digest validation)
6. Error handling for network failures and authentication issues
7. Unit tests with mocked registry responses

The client should authenticate using stored GitHub tokens and handle common registry errors gracefully. Include logging for debugging registry interactions.
```

### Prompt 7: OCI Manifest Parsing
```
Add OCI manifest parsing to extract plugin metadata. Extend the OCI client by adding:

1. OCI manifest annotation parsing for Obsidian plugin metadata
2. Plugin metadata struct matching expected annotation schema
3. Validation of required plugin metadata fields (name, version, description)
4. Error handling for missing or invalid metadata
5. Integration with existing OCI client to extract annotations
6. Unit tests for manifest parsing with various metadata scenarios

The parser should extract plugin information from OCI manifest annotations and validate it matches Obsidian plugin requirements before proceeding with installation.
```

### Prompt 8: Plugin File Extraction
```
Implement plugin file extraction from OCI artifacts. Build on the OCI client by adding:

1. OCI layer extraction to temporary directory
2. Plugin file structure validation (manifest.json, main.js, etc.)
3. Obsidian plugin manifest validation
4. File permission and security checks
5. Temporary directory cleanup on errors
6. Integration with existing OCI operations
7. Unit tests for extraction and validation logic

The extractor should verify the extracted files form a valid Obsidian plugin before proceeding with verification steps.
```

### Prompt 9: SLSA Provenance Verification
```
Implement SLSA provenance verification. Extend the verification pipeline by adding:

1. SLSA attestation parsing from OCI artifact attestations
2. Workflow verification against expected gillisandrew/dragonglass-poc workflow
3. Signature verification using sigstore libraries
4. Provenance claim validation (source repo, workflow, etc.)
5. Error reporting with specific provenance failures
6. Integration with existing OCI artifact processing
7. Unit tests for provenance verification with test attestations

The verifier should confirm plugins were built using the authorized workflow and report detailed information about provenance verification results.
```

### Prompt 10: SPDX SBOM Parsing
```
Implement SPDX SBOM parsing and analysis. Build on the verification pipeline by adding:

1. SPDX document parsing from OCI attestations
2. Dependency extraction and analysis
3. Package relationship mapping
4. License information extraction
5. SBOM validation and completeness checks
6. Integration with existing verification workflow
7. Unit tests for SPDX parsing with various SBOM formats

The parser should extract comprehensive dependency information from SPDX SBOMs and prepare it for vulnerability analysis.
```

### Prompt 11: Vulnerability Scanning Integration
```
Implement vulnerability scanning using SBOM data. Extend the verification pipeline by adding:

1. Integration with vulnerability databases (NVD, GitHub Security Advisory)
2. CVE lookup for SBOM dependencies
3. Severity assessment and filtering
4. Plugin package vs. dependency vulnerability distinction
5. CVE database link generation
6. Vulnerability reporting with actionable information
7. Unit tests for vulnerability detection with known CVEs

The scanner should identify vulnerabilities in plugin dependencies and distinguish between direct plugin vulnerabilities (blocking) and transitive dependency issues (warning).
```

### Prompt 12: Verification Results Presentation
```
Implement verification results presentation and user interaction. Build on all verification components by adding:

1. Comprehensive verification result aggregation
2. Terminal UI for presenting verification findings
3. User prompt system for acknowledgment
4. Colored output for different severity levels
5. Detailed reporting with links to CVEs and repositories
6. User decision handling (proceed/abort)
7. Unit tests for result presentation and user interaction

The presenter should clearly communicate verification results and guide users through security decisions with appropriate warnings and acknowledgment flows.
```

### Prompt 13: Plugin Installation
```
Implement plugin installation to Obsidian directories. Build on the complete verification pipeline by adding:

1. .obsidian/plugins/ directory discovery and creation
2. Plugin installation with conflict detection
3. File extraction to final plugin directory
4. Lockfile updates with installation metadata
5. Installation rollback on errors
6. Permission and ownership handling
7. Unit tests for installation process including error scenarios

The installer should handle the final step of placing verified plugins into Obsidian's plugin directory and maintaining accurate lockfile state.
```

### Prompt 14: List Installed Plugins
```
Implement the list command functionality. Build on existing lockfile and plugin management by adding:

1. Lockfile reading and plugin enumeration
2. Plugin status verification (installed vs. lockfile)
3. Formatted output showing plugin details
4. Table-based display with plugin name, version, and verification status
5. Filtering options for different plugin states
6. Integration with existing plugin management infrastructure
7. Unit tests for listing functionality with various plugin states

The list command should provide clear visibility into installed verified plugins and their current status.
```

### Prompt 15: Verify Without Installation
```
Implement the verify-only command. Build on the complete verification pipeline by adding:

1. Verification workflow without installation steps
2. Complete verification result reporting
3. Integration with existing verification components
4. Output formatting for verification-only results
5. Performance optimization for verify-only operations
6. Comprehensive error handling and reporting
7. Unit tests for verify-only functionality

The verify command should run the complete verification pipeline and present results without modifying the system, allowing users to preview verification results before installation.
```

## Integration and Testing Strategy

Each prompt builds incrementally on previous work, ensuring:
- No orphaned or unused code
- Each step produces a working CLI with expanded functionality
- Clear integration points between components
- Comprehensive testing at each step
- Proper error handling and user experience

## Final Integration

The final step integrates all components into a cohesive CLI tool that:
- Authenticates with GitHub App device flow
- Downloads and verifies OCI artifacts from ghcr.io
- Performs comprehensive security verification (SLSA, SBOM, vulnerabilities)
- Installs verified plugins to Obsidian directories
- Maintains lockfile state for tracking and management
- Provides clear user feedback and security warnings

This approach ensures steady progress with working software at each milestone while building toward the complete specification requirements.