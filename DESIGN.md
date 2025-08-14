# DESIGN.md

# kube-auth-proxy Design Document

## Overview

This design document outlines the development of kube-auth-proxy, an authentication proxy that handles both external OIDC providers and OpenShift's internal OAuth service. This project is derived from the RHOAI + BYOIDC document requirements and focuses on creating a focused, FIPS-compliant authentication solution.

## User Stories

### DevOps Administrator Stories

- **US-001**: As a devops admin, I can configure the proxy to handle OIDC authentication to any valid OIDC provider.
- **US-002**: As a devops admin, I can configure the proxy to handle OAuth authentication to the internal OpenShift OAuth service.
- **US-003**: As a devops admin, I can validate that the proxy image passes all necessary FIPS checks.

## Requirements

### Functional Requirements

- **FR-001**: The project has an authentication provider for OpenShift OAuth
- **FR-002**: The project has an authentication provider for generic OIDC providers
- **FR-003**: The project only supports OIDC and OpenShift OAuth (all other providers removed)
- **FR-004**: The project allows for returning a static 200/OK after auth validation for Envoy ext_authz compatibility
- **FR-005**: Make startup arguments compliant with ODH/RHOAI's usage of oauth-proxy
- **FR-006**: The final image should be a drop-in replacement for current oauth-proxy sidecars

### Non-Functional Requirements

- **NFR-001**: The project has a new Dockerfile.redhat which builds a FIPS compliant image
- **NFR-002**: An automated GitHub workflow checks PR commits and branch commits for FIPS compliance with https://github.com/openshift/check-payload
- **NFR-003**: The project exists in both the opendatahub-io and the red-hat-data-services GitHub organizations with commit syncs setup between the 2

## Proposed Architecture

### Repository Setup

1. **Fork Creation**: Make a disconnected fork of https://github.com/oauth2-proxy/oauth2-proxy into the opendatahub-io organization
2. **Repository Rename**: Rename the repository to "kube-auth-proxy"
3. **Dual Organization**: Establish the project in both opendatahub-io and red-hat-data-services GitHub organizations with commit synchronization

### Implementation Strategy

#### Provider Consolidation

- Remove all non-OIDC providers from oauth2-proxy
- Copy the OpenShift provider from https://github.com/openshift/oauth-proxy
- Use cursor.ai by cloning both repositories and requesting file copying and fixes

#### Compatibility Layer

- Add argument aliases for arguments that have different names between oauth2-proxy and oauth-proxy
- Ensure either argument format can be used

#### Configuration Enhancements

- Add support for reading secrets from files where necessary
- Validate upstream headers are compliant with current usage of oauth-proxy

#### Build System

- Copy the Dockerfile to Dockerfile.redhat and set relevant FIPS arguments
- Isolate and remove unused dependencies

#### Documentation Updates

- Check if any license files need to change
- Fix the README.md to explain the origin of the project

## Development Conventions

To facilitate generative coding on this project, the following conventions are defined:

- **README.md**: General project information suitable for users
- **DESIGN.md**: An LLM generated document based on inputs of high level requirements, used to provide context to all future LLM interactions
- **LIFECYCLE.md**: Keeps track of the maintenance and distribution of this project

## Security Considerations

### FIPS Compliance

- **SEC-001**: The project must have the ability to pass a designed-for-FIPS check via the check-payload tool
- **SEC-002**: Dockerfile.redhat must include appropriate FIPS compilation flags and dependencies

### Authentication Security

- **SEC-003**: Secure handling of OAuth tokens and OIDC credentials
- **SEC-004**: Proper validation of authentication flows for both OpenShift OAuth and external OIDC providers

## Quality Assurance Considerations

### Testing Strategy

- **QA-001**: Implement test coverage via GitHub workflows within the project
- **QA-002**: ODH and RHOAI integration testing will be handled as part of the larger BYOIDC project

### Validation Requirements

- **QA-003**: Automated FIPS compliance checking on all commits
- **QA-004**: Compatibility testing with existing oauth-proxy deployments

## Resource Considerations

### Performance Planning

- **RES-001**: Schedule a meeting with the performance & scale team to understand load testing requirements for the new project
- **RES-002**: Establish performance benchmarks and monitoring for the authentication proxy

### Operational Requirements

- **RES-003**: Ensure the proxy can handle expected authentication loads in production environments
- **RES-004**: Plan for resource consumption monitoring and optimization

## Implementation Roadmap

### Phase 1: Foundation
- [x] Create repository fork and rename
- [x] Remove unnecessary providers
- [x] Integrate OpenShift OAuth provider

### Phase 2: Compatibility
- [ ] Implement argument aliases
- [ ] Add file-based secret reading
- [ ] Validate header compatibility

### Phase 3: FIPS Compliance
- [ ] Create Dockerfile.redhat
- [ ] Implement FIPS compliance checking
- [ ] Set up automated validation workflows

### Phase 4: Integration
- [ ] Set up dual organization presence
- [ ] Implement commit synchronization
- [ ] Prepare for ODH/RHOAI integration

## Success Criteria

- Successfully authenticates against both OpenShift OAuth and external OIDC providers
- Passes all FIPS compliance checks
- Serves as a drop-in replacement for existing oauth-proxy sidecars
- Maintains compatibility with current ODH/RHOAI deployments
- Achieves performance targets established by the performance & scale team

## Current Status

As of the latest implementation, the following work has been completed:

### ✅ Provider Consolidation (Phase 1)
- **Removed Legacy Providers**: All non-OIDC providers (Google, GitHub, Azure, etc.) have been successfully removed from the codebase
- **OIDC-Only Support**: The project now exclusively supports OIDC providers
- **Configuration Updates**: Provider configuration structures and validation logic updated to support only OIDC
- **Test Suite Fixes**: All test suites updated to work with OIDC-only configuration

### ✅ OpenShift OAuth Integration (FR-001)
- **OpenShift OAuth Provider**: Successfully integrated OpenShift OAuth provider with comprehensive authentication support
- **Configuration Options**: Added legacy options support for OpenShift OAuth compatibility 
- **Documentation & Examples**: Created detailed examples for both manual OAuth client setup and service account configurations
- **Test Coverage**: Implemented comprehensive test suite for OpenShift OAuth provider functionality

### 🔄 In Progress
- **FIPS Compliance**: Dockerfile.redhat and FIPS validation workflows needed (NFR-001, NFR-002)
- **Compatibility Layer**: Argument aliases for oauth-proxy compatibility needed (FR-005)

### 📋 Pending
- **Dual Organization Setup**: Repository mirroring to red-hat-data-services (NFR-003)
- **Performance Testing**: Coordination with performance & scale team (RES-001)
- **Documentation Updates**: README.md updates reflecting project origin and purpose