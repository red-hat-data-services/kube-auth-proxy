package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/justinas/alice"
	middlewareapi "github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/middleware"
	sessionsapi "github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/sessions"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/logger"
	k8serrors "k8s.io/apimachinery/pkg/util/errors"
)

const oauthRegexFormat = `^sha256~[a-zA-Z0-9_-]+$` // OpenShift OAuth token format

func NewOAuthSessionLoader(sessionLoaders []middlewareapi.TokenToSessionFunc, bearerTokenLoginFallback bool) alice.Constructor {
	os := &oauthSessionLoader{
		oauthRegex:             regexp.MustCompile(oauthRegexFormat),
		sessionLoaders:         sessionLoaders,
		denyInvalidOAuthTokens: !bearerTokenLoginFallback,
	}
	return os.loadSession
}

// oauthSessionLoader is responsible for loading sessions from OAuth bearer tokens in
// Authorization headers (e.g., OpenShift sha256~ tokens).
type oauthSessionLoader struct {
	oauthRegex             *regexp.Regexp
	sessionLoaders         []middlewareapi.TokenToSessionFunc
	denyInvalidOAuthTokens bool
}

// loadSession attempts to load a session from an OAuth token stored in an Authorization
// header within the request.
// If no authorization header is found, or the header is invalid, no session
// will be loaded and the request will be passed to the next handler.
// Or if the OAuth token is invalid and denyInvalidOAuthTokens, return 403 now.
// If a session was loaded by a previous handler, it will not be replaced.
func (o *oauthSessionLoader) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)
		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		if scope.Session != nil {
			// The session was already loaded, pass to the next handler
			next.ServeHTTP(rw, req)
			return
		}

		session, err := o.getOAuthSession(req)
		if err != nil {
			logger.Errorf("Error retrieving session from OAuth token in Authorization header: %v", err)
			if o.denyInvalidOAuthTokens {
				http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		}

		// Add the session to the scope if it was found
		scope.Session = session
		next.ServeHTTP(rw, req)
	})
}

// getOAuthSession loads a session based on an OAuth bearer token in the authorization header.
// (see the config options skip-jwt-bearer-tokens and bearer-token-login-fallback)
func (o *oauthSessionLoader) getOAuthSession(req *http.Request) (*sessionsapi.SessionState, error) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		// No auth header provided, so don't attempt to load a session
		return nil, nil
	}

	token, err := o.findTokenFromHeader(auth)
	if err != nil {
		return nil, err
	}

	if token == "" {
		// Auth header present but no OAuth token found; ignore and pass to next handler
		return nil, nil
	}

	// This leading error message only occurs if all session loaders fail
	errs := []error{errors.New("unable to verify OAuth bearer token")}
	for _, loader := range o.sessionLoaders {
		session, err := loader(req.Context(), token)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		return session, nil
	}

	return nil, k8serrors.NewAggregate(errs)
}

// findTokenFromHeader finds a valid OAuth bearer token from the Authorization header of a given request.
func (o *oauthSessionLoader) findTokenFromHeader(header string) (string, error) {
	tokenType, token, err := splitAuthHeader(header)
	if err != nil {
		return "", err
	}

	if tokenType == authTypeBearer && o.oauthRegex.MatchString(token) {
		// Found an OAuth bearer token (e.g., OpenShift sha256~ tokens)
		return token, nil
	}

	if tokenType == authTypeBasic {
		// Check if we have an OAuth token masquerading in Basic auth
		return o.getBasicToken(token)
	}

	return "", fmt.Errorf("no valid OAuth bearer token found in authorization header")
}

// getBasicToken tries to extract an OAuth token from the basic value provided.
func (o *oauthSessionLoader) getBasicToken(token string) (string, error) {
	user, password, err := getBasicAuthCredentials(token)
	if err != nil {
		return "", err
	}

	// check user, user+password, or just password for an OAuth token
	if o.oauthRegex.MatchString(user) {
		if password == "x-oauth-basic" || // #nosec G101 -- Support blank passwords or magic `x-oauth-basic` passwords, nothing else
			password == "" {
			return user, nil
		}
	} else if o.oauthRegex.MatchString(password) {
		// support passwords and ignore user
		return password, nil
	}

	return "", fmt.Errorf("invalid basic auth OAuth token found in authorization header")
}
