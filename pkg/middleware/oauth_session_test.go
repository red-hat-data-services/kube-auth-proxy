package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	middlewareapi "github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/middleware"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	// validOAuthToken represents an OpenShift OAuth token (sha256~ prefix format)
	// Example: tokens from `oc whoami -t`
	validOAuthToken = "sha256~abcdefghijklmnopqrstuvwxyz123456"

	// invalidOAuthToken represents a token that doesn't match OAuth format (no sha256~ prefix)
	invalidOAuthToken = "invalid-token-format"

	// validJWTToken represents a JWT token (eyJ... format with three base64 parts)
	// This should NOT be matched by the OAuth loader (it's for the JWT loader)
	validJWTToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

// TestNewOAuthSessionLoader verifies that the OAuth session loader constructor works correctly.
// This is a basic smoke test to ensure the loader can be instantiated.
func TestNewOAuthSessionLoader(t *testing.T) {
	// Setup: Create a simple token validator function
	sessionLoaders := []middlewareapi.TokenToSessionFunc{
		func(ctx context.Context, token string) (*sessions.SessionState, error) {
			return &sessions.SessionState{}, nil
		},
	}

	// Test: Create a new OAuth session loader
	loader := NewOAuthSessionLoader(sessionLoaders, false)

	// Assert: Loader should be created successfully
	assert.NotNil(t, loader)
}

// TestOAuthSessionLoader_ValidBearerToken tests the happy path:
// - Valid OAuth token (sha256~...) sent in Authorization: Bearer header
// - Token is matched by OAuth regex
// - Token validator returns a valid session
// - Expected: Session is created and request succeeds
func TestOAuthSessionLoader_ValidBearerToken(t *testing.T) {
	// Setup: Create a mock token validator that accepts our test OAuth token
	sessionLoaders := []middlewareapi.TokenToSessionFunc{
		func(ctx context.Context, token string) (*sessions.SessionState, error) {
			if token == validOAuthToken {
				return &sessions.SessionState{
					User: "test-user",
				}, nil
			}
			return nil, errors.New("invalid token")
		},
	}

	// Create the OAuth session loader middleware with loginFallback=true
	// loginFallback=true means: if token validation fails, continue to next loader (don't return 403)
	handler := NewOAuthSessionLoader(sessionLoaders, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify that session was created successfully
		scope := middlewareapi.GetRequestScope(r)
		require.NotNil(t, scope.Session, "Session should be created from valid OAuth token")
		assert.Equal(t, "test-user", scope.Session.User, "Session user should match token owner")
		w.WriteHeader(http.StatusOK)
	}))

	// Test: Send request with valid OAuth bearer token
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+validOAuthToken) // Authorization header with OAuth token
	req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	// Assert: Request should succeed with 200 OK
	assert.Equal(t, http.StatusOK, rw.Code, "Valid OAuth token should result in successful authentication")
}

// TestOAuthSessionLoader_JWTTokenNotMatched verifies that JWT tokens are ignored:
// - JWT token (eyJ...) sent in Authorization: Bearer header
// - Token does NOT match OAuth regex (^sha256~...)
// - OAuth loader skips the token entirely
// - Expected: Session remains nil, request passes through (JWT loader will handle it)
//
// This test ensures proper separation of concerns:
// - OAuth loader only handles OAuth tokens (sha256~...)
// - JWT loader handles JWT tokens (eyJ...)
func TestOAuthSessionLoader_JWTTokenNotMatched(t *testing.T) {
	// Setup: Create a validator that would accept any token (but won't be called)
	sessionLoaders := []middlewareapi.TokenToSessionFunc{
		func(ctx context.Context, token string) (*sessions.SessionState, error) {
			// This should NEVER be called for JWT tokens
			return &sessions.SessionState{
				User: "test-user",
			}, nil
		},
	}

	// Create OAuth session loader
	handler := NewOAuthSessionLoader(sessionLoaders, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := middlewareapi.GetRequestScope(r)
		// JWT tokens should not match OAuth regex, so session should be nil
		// (In production, the JWT loader would handle this token)
		assert.Nil(t, scope.Session, "OAuth loader should ignore JWT tokens")
		w.WriteHeader(http.StatusOK)
	}))

	// Test: Send request with JWT bearer token (not OAuth format)
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+validJWTToken) // JWT format, not sha256~
	req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	// Assert: Request passes through successfully (OAuth loader doesn't interfere)
	assert.Equal(t, http.StatusOK, rw.Code, "OAuth loader should pass through JWT tokens unchanged")
}

// TestOAuthSessionLoader_InvalidTokenFormat tests behavior with invalid token format:
// - Token sent that doesn't match OAuth format (no sha256~ prefix)
// - OAuth regex check fails
// - Validator is never called
// - Expected: Session remains nil, request passes through
func TestOAuthSessionLoader_InvalidTokenFormat(t *testing.T) {
	// Setup: Create a validator (but it won't be called due to regex mismatch)
	sessionLoaders := []middlewareapi.TokenToSessionFunc{
		func(ctx context.Context, token string) (*sessions.SessionState, error) {
			// This should NEVER be called for invalid format tokens
			return &sessions.SessionState{
				User: "test-user",
			}, nil
		},
	}

	// Create OAuth session loader
	handler := NewOAuthSessionLoader(sessionLoaders, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := middlewareapi.GetRequestScope(r)
		// Invalid token format should not match OAuth regex, so session should be nil
		assert.Nil(t, scope.Session, "Invalid token format should not create a session")
		w.WriteHeader(http.StatusOK)
	}))

	// Test: Send request with invalid token format (not sha256~ or eyJ...)
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+invalidOAuthToken) // Invalid format
	req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	// Assert: Request passes through (OAuth loader ignores invalid format)
	assert.Equal(t, http.StatusOK, rw.Code, "Invalid token format should be ignored by OAuth loader")
}

// TestOAuthSessionLoader_DenyInvalidTokens tests the strict mode (loginFallback=false):
// - Valid OAuth token format (sha256~...) but validator rejects it
// - loginFallback=false means: return 403 Forbidden immediately
// - Expected: Request denied with 403 Forbidden
//
// This simulates:
// - Token format is correct (matches regex)
// - But OpenShift API says token is invalid/expired
// - With strict mode, access is denied immediately
func TestOAuthSessionLoader_DenyInvalidTokens(t *testing.T) {
	// Setup: Create a validator that always fails
	sessionLoaders := []middlewareapi.TokenToSessionFunc{
		func(ctx context.Context, token string) (*sessions.SessionState, error) {
			return nil, errors.New("token validation failed")
		},
	}

	// Create OAuth session loader with loginFallback=false (strict mode)
	// Strict mode: if OAuth token validation fails, deny immediately
	handler := NewOAuthSessionLoader(sessionLoaders, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This handler should NOT be reached
		w.WriteHeader(http.StatusOK)
	}))

	// Test: Send request with valid OAuth format token that fails validation
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+validOAuthToken) // Format is valid, but will fail validation
	req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	// Assert: Request should be denied with 403 Forbidden
	assert.Equal(t, http.StatusForbidden, rw.Code, "Invalid OAuth token should be denied in strict mode")
}

// TestOAuthSessionLoader_AllowInvalidTokensWithFallback tests the fallback mode (loginFallback=true):
// - Valid OAuth token format (sha256~...) but validator rejects it
// - loginFallback=true means: continue to next loader (don't return 403)
// - Expected: Session remains nil, but request continues (next loader might succeed)
//
// This is useful when:
// - Multiple authentication methods are supported (OAuth, Cookie, Basic Auth)
// - If OAuth fails, try other loaders before denying access
// - Example: User might have a cookie session even if bearer token is invalid
func TestOAuthSessionLoader_AllowInvalidTokensWithFallback(t *testing.T) {
	// Setup: Create a validator that always fails
	sessionLoaders := []middlewareapi.TokenToSessionFunc{
		func(ctx context.Context, token string) (*sessions.SessionState, error) {
			return nil, errors.New("token validation failed")
		},
	}

	// Create OAuth session loader with loginFallback=true (fallback mode)
	// Fallback mode: if OAuth token validation fails, continue to next loader
	handler := NewOAuthSessionLoader(sessionLoaders, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := middlewareapi.GetRequestScope(r)
		// Session should be nil since token validation failed
		assert.Nil(t, scope.Session, "Failed token validation should not create session")
		w.WriteHeader(http.StatusOK)
	}))

	// Test: Send request with valid OAuth format token that fails validation
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+validOAuthToken) // Format is valid, but will fail validation
	req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	// Assert: Request should continue (not denied) - session is nil but request proceeds
	assert.Equal(t, http.StatusOK, rw.Code, "Failed token validation should continue in fallback mode")
}

// TestOAuthSessionLoader_BasicAuthWithToken tests Basic Auth with OAuth token:
// - OAuth token passed as username in Basic Auth header
// - Password is empty
// - Expected: Token is extracted and validated successfully
//
// Use case: CLI tools that support Basic Auth can use: username=token, password=""
// Example: curl -u "sha256~abc:" https://api.example.com
func TestOAuthSessionLoader_BasicAuthWithToken(t *testing.T) {
	// Setup: Create a validator that accepts our test OAuth token
	sessionLoaders := []middlewareapi.TokenToSessionFunc{
		func(ctx context.Context, token string) (*sessions.SessionState, error) {
			if token == validOAuthToken {
				return &sessions.SessionState{
					User: "test-user",
				}, nil
			}
			return nil, errors.New("invalid token")
		},
	}

	// Create OAuth session loader
	handler := NewOAuthSessionLoader(sessionLoaders, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := middlewareapi.GetRequestScope(r)
		require.NotNil(t, scope.Session, "Session should be created from OAuth token in Basic Auth")
		assert.Equal(t, "test-user", scope.Session.User)
		w.WriteHeader(http.StatusOK)
	}))

	// Test: Send request with OAuth token as username in Basic Auth (empty password)
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.SetBasicAuth(validOAuthToken, "") // Token as username, empty password
	req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	// Assert: Request should succeed
	assert.Equal(t, http.StatusOK, rw.Code, "OAuth token in Basic Auth username should work")
}

// TestOAuthSessionLoader_BasicAuthWithOAuthBasicPassword tests GitHub-style OAuth in Basic Auth:
// - OAuth token passed as username
// - Password is "x-oauth-basic" (GitHub convention)
// - Expected: Token is extracted and validated successfully
//
// Use case: GitHub API and similar services use this convention
// Example: curl -u "sha256~abc:x-oauth-basic" https://api.example.com
func TestOAuthSessionLoader_BasicAuthWithOAuthBasicPassword(t *testing.T) {
	// Setup: Create a validator that accepts our test OAuth token
	sessionLoaders := []middlewareapi.TokenToSessionFunc{
		func(ctx context.Context, token string) (*sessions.SessionState, error) {
			if token == validOAuthToken {
				return &sessions.SessionState{
					User: "test-user",
				}, nil
			}
			return nil, errors.New("invalid token")
		},
	}

	// Create OAuth session loader
	handler := NewOAuthSessionLoader(sessionLoaders, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := middlewareapi.GetRequestScope(r)
		require.NotNil(t, scope.Session, "Session should be created from OAuth token with x-oauth-basic password")
		assert.Equal(t, "test-user", scope.Session.User)
		w.WriteHeader(http.StatusOK)
	}))

	// Test: Send request with OAuth token as username and "x-oauth-basic" as password
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.SetBasicAuth(validOAuthToken, "x-oauth-basic") // Token as username, "x-oauth-basic" as password
	req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	// Assert: Request should succeed
	assert.Equal(t, http.StatusOK, rw.Code, "OAuth token with x-oauth-basic password should work")
}

// TestOAuthSessionLoader_BasicAuthWithTokenAsPassword tests OAuth token as password:
// - Username is some arbitrary value
// - OAuth token passed as password in Basic Auth header
// - Expected: Token is extracted from password field and validated successfully
//
// Use case: Some tools/APIs pass tokens as the password field
// Example: curl -u "username:sha256~abc" https://api.example.com
func TestOAuthSessionLoader_BasicAuthWithTokenAsPassword(t *testing.T) {
	// Setup: Create a validator that accepts our test OAuth token
	sessionLoaders := []middlewareapi.TokenToSessionFunc{
		func(ctx context.Context, token string) (*sessions.SessionState, error) {
			if token == validOAuthToken {
				return &sessions.SessionState{
					User: "test-user",
				}, nil
			}
			return nil, errors.New("invalid token")
		},
	}

	// Create OAuth session loader
	handler := NewOAuthSessionLoader(sessionLoaders, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := middlewareapi.GetRequestScope(r)
		require.NotNil(t, scope.Session, "Session should be created from OAuth token in Basic Auth password")
		assert.Equal(t, "test-user", scope.Session.User)
		w.WriteHeader(http.StatusOK)
	}))

	// Test: Send request with OAuth token as password in Basic Auth
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.SetBasicAuth("someuser", validOAuthToken) // Any username, token as password
	req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	// Assert: Request should succeed
	assert.Equal(t, http.StatusOK, rw.Code, "OAuth token in Basic Auth password should work")
}

// TestOAuthSessionLoader_NoAuthHeader tests behavior when no auth header is present:
// - No Authorization header in request
// - No Basic Auth header
// - Expected: OAuth loader does nothing, session remains nil, request continues
//
// This is the normal case for browser-based requests (use cookies instead)
func TestOAuthSessionLoader_NoAuthHeader(t *testing.T) {
	// Setup: Create a validator (but it won't be called since no auth header)
	sessionLoaders := []middlewareapi.TokenToSessionFunc{
		func(ctx context.Context, token string) (*sessions.SessionState, error) {
			// This should NEVER be called when no auth header is present
			return &sessions.SessionState{
				User: "test-user",
			}, nil
		},
	}

	// Create OAuth session loader
	handler := NewOAuthSessionLoader(sessionLoaders, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := middlewareapi.GetRequestScope(r)
		// No auth header means no session from OAuth loader
		assert.Nil(t, scope.Session, "No auth header should result in no session")
		w.WriteHeader(http.StatusOK)
	}))

	// Test: Send request without any Authorization header
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	// No Authorization header set
	req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	// Assert: Request should continue (OAuth loader does nothing)
	assert.Equal(t, http.StatusOK, rw.Code, "Request without auth header should pass through")
}

// TestOAuthSessionLoader_ExistingSession tests behavior when session already exists:
// - Request already has a session (e.g., from a previous loader like Cookie loader)
// - OAuth token is present in Authorization header
// - Expected: Existing session is preserved, OAuth loader does nothing
//
// This ensures:
// - First successful loader wins
// - Later loaders don't override existing sessions
// - Example: Cookie session takes precedence over bearer token
func TestOAuthSessionLoader_ExistingSession(t *testing.T) {
	// Setup: Create a validator that would create a different session
	sessionLoaders := []middlewareapi.TokenToSessionFunc{
		func(ctx context.Context, token string) (*sessions.SessionState, error) {
			// This would create "new-user", but should NOT be called
			return &sessions.SessionState{
				User: "new-user",
			}, nil
		},
	}

	// Create OAuth session loader
	handler := NewOAuthSessionLoader(sessionLoaders, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := middlewareapi.GetRequestScope(r)
		require.NotNil(t, scope.Session, "Session should exist")
		// Session should still be "existing-user", not "new-user"
		assert.Equal(t, "existing-user", scope.Session.User, "Existing session should not be overwritten")
		w.WriteHeader(http.StatusOK)
	}))

	// Test: Send request with OAuth token but already has an existing session
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+validOAuthToken) // Token is present
	req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{
		Session: &sessions.SessionState{
			User: "existing-user", // Pre-existing session (e.g., from cookie)
		},
	})

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	// Assert: Request should succeed with existing session unchanged
	assert.Equal(t, http.StatusOK, rw.Code, "Existing session should be preserved")
}

// TestOAuthSessionLoader_MultipleLoaders tests fallback behavior with multiple validators:
// - Multiple token validators configured (e.g., for different OAuth providers)
// - First two validators fail
// - Third validator succeeds
// - Expected: Third validator's session is used
//
// Use case: Supporting multiple OAuth providers (OpenShift + External OAuth)
// - Try OpenShift OAuth API first
// - If that fails, try external OAuth provider
// - Use the first one that succeeds
func TestOAuthSessionLoader_MultipleLoaders(t *testing.T) {
	// Setup: Create three validators, only the third one succeeds
	sessionLoaders := []middlewareapi.TokenToSessionFunc{
		func(ctx context.Context, token string) (*sessions.SessionState, error) {
			// First loader: fails (e.g., OpenShift OAuth API returns 401)
			return nil, errors.New("first loader failed")
		},
		func(ctx context.Context, token string) (*sessions.SessionState, error) {
			// Second loader: fails (e.g., wrong OAuth provider)
			return nil, errors.New("second loader failed")
		},
		func(ctx context.Context, token string) (*sessions.SessionState, error) {
			// Third loader: succeeds (e.g., external OAuth provider validates token)
			if token == validOAuthToken {
				return &sessions.SessionState{
					User: "test-user-from-third-loader",
				}, nil
			}
			return nil, errors.New("third loader failed")
		},
	}

	// Create OAuth session loader with all three validators
	handler := NewOAuthSessionLoader(sessionLoaders, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := middlewareapi.GetRequestScope(r)
		require.NotNil(t, scope.Session, "Session should be created by third loader")
		// Session should be from third loader
		assert.Equal(t, "test-user-from-third-loader", scope.Session.User, "Third loader should succeed after first two fail")
		w.WriteHeader(http.StatusOK)
	}))

	// Test: Send request with OAuth token
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+validOAuthToken)
	req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	// Assert: Request should succeed with session from third loader
	assert.Equal(t, http.StatusOK, rw.Code, "Third loader should create session after first two fail")
}
