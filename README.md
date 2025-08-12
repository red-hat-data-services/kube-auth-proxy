# kube-auth-proxy

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

kube-auth-proxy is a focused, FIPS-compliant authentication proxy designed specifically for OpenShift Data Hub (ODH) and Red Hat OpenShift AI (RHOAI) environments. It provides secure authentication through both external OIDC providers and OpenShift's internal OAuth service, serving as a drop-in replacement for existing oauth-proxy sidecars for authentication purposes only.

This project is derived from oauth2-proxy but has been streamlined to support only the authentication methods required for enterprise Kubernetes environments, with a strong emphasis on FIPS compliance and compatibility with existing ODH/RHOAI deployments.

## Key Features

- **OIDC Authentication**: Support for any standards-compliant OIDC provider
- **OpenShift OAuth Integration**: Native support for OpenShift's internal OAuth service
- **FIPS Compliance**: Built with FIPS-compliant dependencies and compilation flags
- **Drop-in Compatibility**: Designed to replace existing oauth-proxy sidecars for authentication without configuration changes
- **Envoy ext_authz Support**: Compatible with Envoy's external authorization framework
- **Streamlined Codebase**: Focused implementation with unnecessary providers removed

## Architecture

kube-auth-proxy acts as a reverse proxy that intercepts requests to your applications and handles authentication through either:

1. **External OIDC Providers**: Standard OIDC flow with configurable providers
2. **OpenShift OAuth**: Integration with OpenShift's built-in authentication system

Once authenticated, the proxy forwards requests to upstream applications with appropriate headers containing user identity and authorization information.

## Get Started

### Installation

#### Container Images

**⚠️ Container images are currently under development (TBD).** Once available, kube-auth-proxy will be distributed as container images built for multiple architectures:

- **Standard Images**: Based on distroless for minimal attack surface
- **FIPS Images**: FIPS-compliant builds for enterprise environments

```bash
# Standard image (TBD)
# podman pull quay.io/opendatahub-io/kube-auth-proxy:latest

# FIPS-compliant image (TBD)
# podman pull quay.io/opendatahub-io/kube-auth-proxy:latest-fips
```

#### Binary Releases

Pre-compiled binaries are available for all major architectures on the [releases page](https://github.com/opendatahub-io/kube-auth-proxy/releases/latest).

### Configuration

kube-auth-proxy supports configuration through command-line arguments and environment variables. It maintains compatibility with oauth-proxy argument formats for seamless migration.

#### OIDC Provider Example

```bash
kube-auth-proxy \
  --provider=oidc \
  --oidc-issuer-url=https://your-oidc-provider.com \
  --client-id=your-client-id \
  --client-secret=your-client-secret \
  --upstream=http://your-app:8080 \
  --http-address=0.0.0.0:4180
```

#### OpenShift OAuth Example

```bash
kube-auth-proxy \
  --provider=openshift \
  --openshift-service-ca=/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt \
  --upstream=http://your-app:8080 \
  --http-address=0.0.0.0:4180
```

For detailed configuration options, see the [Configuration Documentation](docs/configuration.md).

## Supported Providers

kube-auth-proxy supports the following authentication providers:

- **OIDC**: Any standards-compliant OpenID Connect provider
- **OpenShift OAuth**: OpenShift's built-in authentication system

All other authentication providers have been intentionally removed to maintain focus and reduce the attack surface.

## FIPS Compliance

kube-auth-proxy is built with FIPS compliance as a primary requirement:

- **FIPS-compliant builds**: Available through `Dockerfile.redhat`
- **Automated validation**: CI/CD pipeline includes FIPS compliance checks using [check-payload](https://github.com/openshift/check-payload)
- **Secure dependencies**: Only FIPS-approved cryptographic libraries

## Migration from oauth-proxy

kube-auth-proxy is designed as a drop-in replacement for oauth-proxy authentication in ODH/RHOAI environments:

1. **Argument Compatibility**: Supports both oauth2-proxy and oauth-proxy argument formats
2. **Header Compatibility**: Maintains the same upstream headers as oauth-proxy
3. **Behavior Compatibility**: Preserves expected authentication flows and responses

**Note**: This proxy handles authentication (authn) only. It does not include RBAC or SubjectAccessReview (SAR) authorization capabilities.

## Development

### Building from Source

```bash
# Standard build
make build

# FIPS-compliant build
make build-fips
```

### Running Tests

```bash
make test
```

### Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:

- Code style and conventions
- Testing requirements
- Submission process

## Security

If you believe you have found a security vulnerability, please do **NOT** open an issue or PR. Instead, report it privately by emailing the maintainers listed in the [MAINTAINERS](MAINTAINERS.md) file.

For more details, see our [Security Policy](SECURITY.md).

## Repository History

**2025-08-11:** This repository was created as a disconnected fork of [oauth2-proxy/oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) specifically for OpenShift Data Hub and Red Hat OpenShift AI environments. The project has been streamlined to support only OIDC and OpenShift OAuth providers, with a focus on FIPS compliance and enterprise requirements.

**Original oauth2-proxy History:**

- **2020-03-29:** oauth2-proxy was renamed from `pusher/oauth2_proxy` to `oauth2-proxy/oauth2-proxy`
- **2018-11-27:** oauth2-proxy was forked from [bitly/OAuth2_Proxy](https://github.com/bitly/oauth2_proxy)

This fork maintains the MIT license and acknowledges the excellent foundation provided by the oauth2-proxy community while serving the specific needs of the OpenShift ecosystem.

## License

kube-auth-proxy is distributed under [The MIT License](LICENSE), maintaining compatibility with its oauth2-proxy origins.

## Acknowledgments

This project builds upon the excellent work of the [oauth2-proxy community](https://github.com/oauth2-proxy/oauth2-proxy). We gratefully acknowledge their contributions to the open-source authentication proxy ecosystem.

Special thanks to the OpenShift and Red Hat communities for their guidance on enterprise authentication requirements and FIPS compliance standards.
