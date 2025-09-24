# Dragonglass CLI Development Todo

## Project Status: Phase 3 Complete ✅

### Completed Planning Tasks
- [x] Read and analyze project specification
- [x] Draft detailed development blueprint
- [x] Break blueprint into small, iterative chunks
- [x] Right-size development steps for safe implementation
- [x] Create implementation prompts for each step
- [x] Store comprehensive plan in plan.md
- [x] Create todo.md for state tracking

## Implementation Progress

### Phase 1: Foundation (Steps 1-3) ✅
- [x] Step 1: Project Bootstrap
  - [x] Initialize Go modules and project structure
  - [x] Set up Cobra CLI with subcommands
  - [x] Implement placeholder command handlers
  - [x] Create Makefile and basic build system
  - [x] Verify `dragonglass --help` functionality

- [x] Step 2: Configuration Management
  - [x] Design Config struct for user preferences
  - [x] Implement config file I/O for `.obsidian/` directories
  - [x] Add directory traversal for config discovery
  - [x] Create default configuration and validation
  - [x] Write unit tests for configuration system

- [x] Step 3: Lockfile Management
  - [x] Design Lockfile struct with plugin metadata
  - [x] Implement lockfile CRUD operations
  - [x] Add JSON marshaling with proper field handling
  - [x] Create lockfile versioning system
  - [x] Write comprehensive lockfile unit tests

### Phase 2: Authentication (Steps 4-5) ✅
- [x] Step 4: GitHub App Authentication Structure
  - [x] Implement native GitHub OAuth device flow (no go-gh dependency)
  - [x] Add URL-encoded response parsing for device codes and tokens
  - [x] Create user-friendly auth command flow with device flow instructions
  - [x] Add network error handling and authentication debugging
  - [x] Write authentication unit tests with form-encoded responses

- [x] Step 5: Credential Storage
  - [x] Integrate OS keychain libraries with zalando/go-keyring
  - [x] Implement fallback file storage with proper permissions
  - [x] Add token persistence and retrieval across CLI sessions
  - [x] Create credential cleanup functionality for logout
  - [x] Write cross-platform storage tests
  - [x] Remove go-gh library dependency and implement native auth integration

### Phase 3: OCI Integration (Steps 6-8) ✅
- [x] Step 6: Basic OCI Registry Client
  - [x] Integrate oras-go OCI library with native authentication
  - [x] Implement ORAS auth.StaticCredential for GitHub token auth
  - [x] Add artifact downloading with progress indication
  - [x] Create comprehensive registry error handling
  - [x] Write OCI client unit tests
  - [x] Successfully test authentication with ghcr.io/gillisandrew/dragonglass-poc

- [x] Step 7: OCI Manifest Parsing
  - [x] Parse OCI manifest annotations
  - [x] Extract Obsidian plugin metadata
  - [x] Add metadata validation logic
  - [x] Integrate with OCI client operations
  - [x] Write manifest parsing tests

- [x] Step 8: Plugin File Extraction
  - [x] Implement OCI layer extraction
  - [x] Add plugin structure validation
  - [x] Create file security checks
  - [x] Add temporary directory management
  - [x] Write extraction unit tests

### Phase 4: Verification Pipeline (Steps 9-12) ⚡ IN PROGRESS
- [x] Step 9: SLSA Provenance Verification ✅
  - [x] Parse SLSA attestations from OCI artifacts with layer extraction
  - [x] Implement comprehensive workflow verification logic
  - [x] Add Sigstore bundle parsing and DSSE envelope validation
  - [x] Create detailed error reporting with clean output
  - [x] Write provenance verification tests with protojson support
  - [x] Validate against trusted builder: `https://github.com/gillisandrew/dragonglass-poc/.github/workflows/build.yml@refs/heads/main`

- [ ] Step 10: SPDX SBOM Parsing
  - [ ] Integrate SPDX parsing libraries
  - [ ] Extract dependency information
  - [ ] Map package relationships
  - [ ] Add SBOM validation checks
  - [ ] Write SBOM parsing tests

- [ ] Step 11: Vulnerability Scanning Integration
  - [ ] Integrate vulnerability databases
  - [ ] Implement CVE lookup for dependencies
  - [ ] Add severity assessment logic
  - [ ] Create CVE link generation
  - [ ] Write vulnerability scanning tests

- [ ] Step 12: Verification Results Presentation
  - [ ] Aggregate verification results
  - [ ] Create terminal UI for result display
  - [ ] Implement user acknowledgment prompts
  - [ ] Add colored output and formatting
  - [ ] Write UI interaction tests

### Phase 5: Plugin Management (Steps 13-15)
- [ ] Step 13: Plugin Installation
  - [ ] Implement Obsidian directory discovery
  - [ ] Add plugin installation with conflict handling
  - [ ] Update lockfile with installation metadata
  - [ ] Create installation rollback logic
  - [ ] Write installation unit tests

- [ ] Step 14: List Installed Plugins
  - [ ] Read lockfile and enumerate plugins
  - [ ] Verify plugin installation status
  - [ ] Create formatted table output
  - [ ] Add filtering and sorting options
  - [ ] Write listing functionality tests

- [ ] Step 15: Verify Without Installation
  - [ ] Implement verification-only workflow
  - [ ] Optimize verification performance
  - [ ] Create verify-only result formatting
  - [ ] Add comprehensive error handling
  - [ ] Write verify-only unit tests

## Current Priority
**Next Action**: Begin Phase 5, Step 13 - Plugin Installation (Strategic Pivot)

## Recent Achievements ✨
- **Completed SLSA Provenance Verification**: Implemented comprehensive DSSE envelope parsing and workflow verification
- **Validated Trusted Builder**: Successfully verifying against `https://github.com/gillisandrew/dragonglass-poc/.github/workflows/build.yml@refs/heads/main`
- **Enhanced Attestation Discovery**: Added OCI referrers API support for finding attestations
- **Improved Error Reporting**: Clean, detailed verification output with proper failure diagnostics

## Notes
- Each step should include comprehensive unit tests
- Integration tests should be added after major phases
- All code should follow Go best practices and conventions
- Error handling and user experience are critical at each step
- Each step should produce a working CLI with expanded functionality

## Success Criteria
- [ ] All 15 implementation steps completed
- [ ] Full end-to-end CLI functionality working
- [ ] Comprehensive test coverage (>80%)
- [ ] Documentation and help text complete
- [ ] Cross-platform builds for macOS and Linux
- [ ] Security verification pipeline fully operational