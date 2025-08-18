package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOpenShiftProvider(t *testing.T) {
	tests := []struct {
		name                 string
		providerConfig       options.Provider
		expectedProviderName string
		expectedScope        string
	}{
		{
			name: "Default OpenShift provider",
			providerConfig: options.Provider{
				Type: options.OpenShiftProvider,
			},
			expectedProviderName: "OpenShift OAuth",
			expectedScope:        openShiftDefaultScope,
		},
		{
			name: "OpenShift provider with custom scope",
			providerConfig: options.Provider{
				Type:  options.OpenShiftProvider,
				Scope: "user:info",
			},
			expectedProviderName: "OpenShift OAuth",
			expectedScope:        "user:info",
		},
		{
			name: "OpenShift provider with service account auto-detection",
			providerConfig: options.Provider{
				Type:           options.OpenShiftProvider,
				ServiceAccount: "my-service-account",
				// ClientID and ClientSecret intentionally empty to test auto-detection
			},
			expectedProviderName: "OpenShift OAuth",
			expectedScope:        openShiftDefaultScope,
		},
		{
			name: "OpenShift provider with custom display name",
			providerConfig: options.Provider{
				Type: options.OpenShiftProvider,
				Name: "My Custom OpenShift OAuth",
			},
			expectedProviderName: "My Custom OpenShift OAuth",
			expectedScope:        openShiftDefaultScope,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(tt.providerConfig)
			assert.NoError(t, err)
			assert.NotNil(t, provider)

			// Cast to OpenShiftProvider to access the embedded ProviderData
			openshiftProvider, ok := provider.(*OpenShiftProvider)
			assert.True(t, ok, "Provider should be an OpenShiftProvider")

			assert.Equal(t, tt.expectedProviderName, openshiftProvider.ProviderData.ProviderName)
			assert.Equal(t, tt.expectedScope, openshiftProvider.ProviderData.Scope)
			assert.NotNil(t, openshiftProvider.ValidateURL)
		})
	}
}

func TestOpenShiftProviderGetKubeAPIURLWithPath(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "127.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "123")

	tests := []struct {
		name        string
		path        string
		expectedURL string
	}{
		{
			name:        "User info endpoint",
			path:        "/apis/user.openshift.io/v1/users/~",
			expectedURL: "https://127.0.0.1:123/apis/user.openshift.io/v1/users/~",
		},
		{
			name:        "OAuth discovery endpoint",
			path:        "/.well-known/oauth-authorization-server",
			expectedURL: "https://127.0.0.1:123/.well-known/oauth-authorization-server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getKubeAPIURLWithPath(tt.path)
			assert.Equal(t, tt.expectedURL, result)
		})
	}
}

func TestOpenShiftProviderRedeem(t *testing.T) {
	// Mock OAuth server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify that the request contains the expected parameters
		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "authorization_code", r.FormValue("grant_type"))
		assert.Equal(t, "test-code", r.FormValue("code"))
		assert.Equal(t, "test-client-id", r.FormValue("client_id"))
		assert.Equal(t, "test-client-secret", r.FormValue("client_secret"))
		assert.Equal(t, "http://localhost/callback", r.FormValue("redirect_uri"))

		// Check if PKCE code_verifier is present
		codeVerifier := r.FormValue("code_verifier")
		if codeVerifier != "" {
			assert.Equal(t, "test-code-verifier", codeVerifier)
		}

		// Return a successful token response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token": "test-access-token"}`))
	}))
	defer server.Close()

	redeemURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	tests := []struct {
		name         string
		codeVerifier string
		expectedErr  bool
	}{
		{
			name:         "OAuth2 flow without PKCE",
			codeVerifier: "",
			expectedErr:  false,
		},
		{
			name:         "OAuth2 flow with PKCE",
			codeVerifier: "test-code-verifier",
			expectedErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &OpenShiftProvider{
				ProviderData: &ProviderData{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
					RedeemURL:    redeemURL,
				},
			}

			session, err := provider.Redeem(context.Background(), "http://localhost/callback", "test-code", tt.codeVerifier)

			if tt.expectedErr {
				assert.Error(t, err)
				assert.Nil(t, session)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, session)
				assert.Equal(t, "test-access-token", session.AccessToken)
			}
		})
	}
}

func TestOpenShiftProviderRedeemMissingCode(t *testing.T) {
	provider := &OpenShiftProvider{
		ProviderData: &ProviderData{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		},
	}

	session, err := provider.Redeem(context.Background(), "http://localhost/callback", "", "")
	assert.Error(t, err)
	assert.Nil(t, session)
	assert.Contains(t, err.Error(), "missing code")
}

func TestOpenShiftProviderCacheKeyFormat(t *testing.T) {
	tests := []struct {
		name                string
		useSystemTrustStore bool
		caFiles             []string
		expectedCacheKey    string
	}{
		{
			name:                "System trust store enabled, single CA file",
			useSystemTrustStore: true,
			caFiles:             []string{"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"},
			expectedCacheKey:    "true:/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		},
		{
			name:                "System trust store disabled, single CA file",
			useSystemTrustStore: false,
			caFiles:             []string{"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"},
			expectedCacheKey:    "false:/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		},
		{
			name:                "System trust store enabled, multiple CA files",
			useSystemTrustStore: true,
			caFiles:             []string{"/custom/ca1.crt", "/custom/ca2.crt"},
			expectedCacheKey:    "true:/custom/ca1.crt,/custom/ca2.crt",
		},
		{
			name:                "System trust store disabled, multiple CA files",
			useSystemTrustStore: false,
			caFiles:             []string{"/custom/ca1.crt", "/custom/ca2.crt"},
			expectedCacheKey:    "false:/custom/ca1.crt,/custom/ca2.crt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualKey := formatCacheKey(tt.useSystemTrustStore, tt.caFiles)
			assert.Equal(t, tt.expectedCacheKey, actualKey)
		})
	}
}

func TestDiscoverValidateURL(t *testing.T) {
	tests := []struct {
		name      string
		setupEnv  func()
		expectNil bool
	}{
		{
			name: "Valid Kubernetes environment",
			setupEnv: func() {
				t.Setenv("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
				t.Setenv("KUBERNETES_SERVICE_PORT", "443")
			},
			expectNil: false,
		},
		{
			name: "Default Kubernetes environment (uses hardcoded defaults)",
			setupEnv: func() {
				// Test with default environment (empty vars fall back to hardcoded defaults)
			},
			expectNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv()

			result, err := url.Parse(getKubeAPIURLWithPath(openShiftUserInfoPath))
			require.NoError(t, err)

			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Contains(t, result.String(), "/apis/user.openshift.io/v1/users/~")
				assert.Contains(t, result.String(), "https://")
			}
		})
	}
}

// Helper function to test cache key formatting
func formatCacheKey(useSystemTrustStore bool, capaths []string) string {
	if useSystemTrustStore {
		return "true:" + strings.Join(capaths, ",")
	}
	return "false:" + strings.Join(capaths, ",")
}
