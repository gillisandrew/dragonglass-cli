# Dragonglass CLI Development Todo

## Project Status: Planning Complete ✅

### Completed Planning Tasks
- [x] Read and analyze project specification
- [x] Draft detailed development blueprint
- [x] Break blueprint into small, iterative chunks
- [x] Right-size development steps for safe implementation
- [x] Create implementation prompts for each step
- [x] Store comprehensive plan in plan.md
- [x] Create todo.md for state tracking

## Implementation Phase: Ready to Begin

### Phase 1: Foundation (Steps 1-3)
- [ ] Step 1: Project Bootstrap
  - [ ] Initialize Go modules and project structure
  - [ ] Set up Cobra CLI with subcommands
  - [ ] Implement placeholder command handlers
  - [ ] Create Makefile and basic build system
  - [ ] Verify `dragonglass --help` functionality

- [ ] Step 2: Configuration Management
  - [ ] Design Config struct for user preferences
  - [ ] Implement config file I/O for `.obsidian/` directories
  - [ ] Add directory traversal for config discovery
  - [ ] Create default configuration and validation
  - [ ] Write unit tests for configuration system

- [ ] Step 3: Lockfile Management
  - [ ] Design Lockfile struct with plugin metadata
  - [ ] Implement lockfile CRUD operations
  - [ ] Add JSON marshaling with proper field handling
  - [ ] Create lockfile versioning system
  - [ ] Write comprehensive lockfile unit tests

### Phase 2: Authentication (Steps 4-5)
- [ ] Step 4: GitHub App Authentication Structure
  - [ ] Implement GitHub OAuth device flow
  - [ ] Add token handling and validation
  - [ ] Create user-friendly auth command flow
  - [ ] Add network error handling
  - [ ] Write authentication unit tests

- [ ] Step 5: Credential Storage
  - [ ] Integrate OS keychain libraries
  - [ ] Implement fallback file storage with encryption
  - [ ] Add token persistence and retrieval
  - [ ] Create credential cleanup functionality
  - [ ] Write cross-platform storage tests

### Phase 3: OCI Integration (Steps 6-8)
- [ ] Step 6: Basic OCI Registry Client
  - [ ] Integrate oras-go OCI library
  - [ ] Implement ghcr.io authentication
  - [ ] Add artifact downloading with progress
  - [ ] Create registry error handling
  - [ ] Write OCI client unit tests

- [ ] Step 7: OCI Manifest Parsing
  - [ ] Parse OCI manifest annotations
  - [ ] Extract Obsidian plugin metadata
  - [ ] Add metadata validation logic
  - [ ] Integrate with OCI client operations
  - [ ] Write manifest parsing tests

- [ ] Step 8: Plugin File Extraction
  - [ ] Implement OCI layer extraction
  - [ ] Add plugin structure validation
  - [ ] Create file security checks
  - [ ] Add temporary directory management
  - [ ] Write extraction unit tests

### Phase 4: Verification Pipeline (Steps 9-12)
- [ ] Step 9: SLSA Provenance Verification
  - [ ] Parse SLSA attestations from OCI artifacts
  - [ ] Implement workflow verification logic
  - [ ] Add sigstore signature verification
  - [ ] Create detailed error reporting
  - [ ] Write provenance verification tests

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
**Next Action**: Begin Phase 1, Step 1 - Project Bootstrap

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