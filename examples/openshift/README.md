# OpenShift OAuth Provider

The OpenShift provider enables `kube-auth-proxy` to authenticate users against OpenShift's built-in OAuth service, providing seamless integration with OpenShift's RBAC and user management.

## Two Approaches Available

### [Manual OAuth Client](manual/)
**Best for**: Full control, traditional OAuth setup, custom client settings
- You create and manage the `OAuthClient` resource
- Client ID matches the OAuth client resource name  
- You manage client secrets manually
- More control over OAuth client configuration

### [Service Account Auto-Detection](service-account/)  
**Best for**: Simple deployment, automatic management, RBAC integration
- Service account acts as the OAuth client (no separate OAuthClient resource)
- Client ID is `system:serviceaccount:<namespace>:<service-account>`
- Service account token used as client secret
- Zero OAuth client management needed

## Common Features

Both approaches provide:
- **Native OpenShift Integration**: Uses OpenShift's built-in OAuth server
- **Access Token Forwarding**: Forwards OAuth tokens for downstream Kubernetes API calls  
- **TLS Certificate Management**: Handles OpenShift's internal CA certificates automatically
- **User Information**: Forwards user identity and email to upstream applications

## Quick Comparison

| Feature | Manual OAuth Client | Service Account Auto-Detection |
|---------|--------------------|---------------------------------|
| **Setup Complexity** | Medium (create OAuth client) | Low (just deploy) |
| **OAuth Client Management** | Manual | None (service account is the client) |
| **Client ID Format** | Your choice | `system:serviceaccount:*` |
| **Secret Management** | Manual | Automatic (service account token) |
| **Customization** | High | Limited |
| **RBAC Integration** | Manual setup | Automatic |

## Access Token Forwarding

Both approaches forward authentication information to upstream applications:

### Headers Forwarded to Upstream
- `X-Forwarded-Access-Token`: OAuth access token for Kubernetes API calls
- `X-Forwarded-User`: Authenticated username from OpenShift
- `X-Forwarded-Email`: User email address (or generated from username)

### Using Tokens for Kubernetes API Access

Your upstream applications can use the forwarded token to make authenticated Kubernetes API calls:

```bash
# Example: Get user information
curl -H "Authorization: Bearer $X_FORWARDED_ACCESS_TOKEN" \
     https://api.cluster.example.com/apis/user.openshift.io/v1/users/~

# Example: List accessible projects  
curl -H "Authorization: Bearer $X_FORWARDED_ACCESS_TOKEN" \
     https://api.cluster.example.com/apis/project.openshift.io/v1/projects
```

> **Note**: Service account-based OAuth clients have limited scopes and can only access resources within their namespace or specific user information. Manual OAuth clients may have broader scope access depending on configuration.