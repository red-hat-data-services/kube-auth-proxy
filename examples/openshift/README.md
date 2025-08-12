# OpenShift OAuth Provider

The OpenShift provider enables `kube-auth-proxy` to authenticate users against OpenShift's built-in OAuth service.

## Basic Usage

### Service Account Auto-Detection (Recommended)

When running inside OpenShift, the proxy can automatically detect OAuth credentials:

```bash
kube-auth-proxy \
  --provider=openshift \
  --openshift-service-account=my-service-account \
  --upstream=http://my-app:8080 \
  --http-address=0.0.0.0:4180
```

**Prerequisites:**
- Service account must exist in the namespace
- Service account must have the OAuth redirect URI annotation:
  ```yaml
  serviceaccounts.openshift.io/oauth-redirecturi.auth: "https://my-app.apps.cluster.com/oauth2/callback"
  ```

### Manual Configuration

```bash
kube-auth-proxy \
  --provider=openshift \
  --login-url=https://oauth-openshift.apps.cluster.com/oauth/authorize \
  --redeem-url=https://oauth-openshift.apps.cluster.com/oauth/token \
  --validate-url=https://api.cluster.com:6443/apis/user.openshift.io/v1/users/~ \
  --client-id=system:serviceaccount:my-namespace:my-sa \
  --client-secret=sha256~abc123... \
  --upstream=http://my-app:8080 \
  --http-address=0.0.0.0:4180
```

## Configuration Options

| Option | Description | Required |
|--------|-------------|----------|
| `--provider=openshift` | Use OpenShift OAuth provider | ✅ |
| `--openshift-service-account` | Service account name for auto-detection | For auto-detection |
| `--upstream` | Backend application URL | ✅ |
| `--http-address` | Proxy listen address | ✅ |

## Custom CA Certificates

For clusters with custom Certificate Authorities, you can specify CA certificate files:

```bash
kube-auth-proxy \
  --provider=openshift \
  --openshift-service-account=my-service-account \
  --provider-ca-file=/etc/ssl/certs/custom-ca.crt \
  --upstream=http://my-app:8080 \
  --http-address=0.0.0.0:4180
```

### oauth-proxy Compatibility

For compatibility with existing `oauth-proxy` configurations, the deprecated `--openshift-ca` flag is also supported:

```bash
# This works but is deprecated - use --provider-ca-file instead
kube-auth-proxy \
  --provider=openshift \
  --openshift-service-account=my-service-account \
  --openshift-ca=/etc/ssl/certs/custom-ca.crt \
  --upstream=http://my-app:8080 \
  --http-address=0.0.0.0:4180
```

**Migration note**: Both flags can be used together, and their values will be merged. However, `--openshift-ca` is deprecated and will be removed in a future version.

## Multiple Upstreams

The proxy supports routing to multiple backend services:

```bash
kube-auth-proxy \
  --provider=openshift \
  --openshift-service-account=my-service-account \
  --upstream=http://frontend:3000/ \
  --upstream=http://api:8080/api/ \
  --http-address=0.0.0.0:4180
```

## Simple Deployment Example

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: auth-proxy
  annotations:
    serviceaccounts.openshift.io/oauth-redirecturi.auth: "https://my-app.apps.cluster.com/oauth2/callback"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      serviceAccountName: auth-proxy
      containers:
      - name: app
        image: my-app:latest
        ports:
        - containerPort: 8080
      - name: auth-proxy
        image: kube-auth-proxy:latest
        args:
        - --provider=openshift
        - --openshift-service-account=auth-proxy
        - --upstream=http://localhost:8080
        - --http-address=0.0.0.0:4180
        ports:
        - containerPort: 4180
```
---

> **Note**: This documentation covers basic, tested functionality. Additional features and deployment patterns will be documented as they are implemented and validated.

For more information, see the [main documentation](../../README.md).