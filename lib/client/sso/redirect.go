/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package sso

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/log"

	"github.com/gravitational/teleport/api/client/proto"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/api/utils/keys"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/secret"
	"github.com/gravitational/teleport/lib/utils"
)

const (
	// LoginSuccessRedirectURL is a redirect URL when login was successful without errors.
	LoginSuccessRedirectURL = "/web/msg/info/login_success"

	// LoginTerminalRedirectURL is a redirect URL when login requires extra
	// action in the terminal, but was otherwise successful in the browser (ex.
	// need a hardware key tap).
	LoginTerminalRedirectURL = "/web/msg/info/login_terminal"

	// LoginFailedRedirectURL is the default redirect URL when an SSO error was encountered.
	LoginFailedRedirectURL = "/web/msg/error/login"

	// LoginFailedBadCallbackRedirectURL is a redirect URL when an SSO error specific to
	// auth connector's callback was encountered.
	LoginFailedBadCallbackRedirectURL = "/web/msg/error/login/callback"

	// LoginFailedUnauthorizedRedirectURL is a redirect URL for when an SSO authenticates successfully,
	// but the user has no matching roles in Teleport.
	LoginFailedUnauthorizedRedirectURL = "/web/msg/error/login/auth"

	// LoginClose is a redirect URL that will close the tab performing the SSO
	// login. It's used when a second tab will be opened due to the first
	// failing (such as an unmet hardware key policy) and the first should be
	// ignored.
	LoginClose = "/web/msg/info/login_close"

	// SAMLSingleLogoutFailedRedirectURL is the default redirect URL when an error was encountered during SAML Single Logout.
	SAMLSingleLogoutFailedRedirectURL = "/web/msg/error/slo"

	// DefaultLoginURL is the default login page.
	DefaultLoginURL = "/web/login"
)

type RedirectorConfig struct {
	// ProxyAddr is the target proxy address
	ProxyAddr string
	// ConnectorID is the OIDC or SAML connector ID to use
	ConnectorID string
	// ConnectorName is the display name of the connector.
	ConnectorName string
	// Protocol is an optional protocol selection
	Protocol string
	// BindAddr is an optional host:port address to bind
	// to for SSO login flows
	BindAddr string
	// CallbackAddr is the optional base URL to give to the user when performing
	// SSO redirect flows.
	CallbackAddr string
	// Browser can be used to pass the name of a browser to override the system
	// default (not currently implemented), or set to 'none' to suppress
	// browser opening entirely.
	Browser string
	// PrivateKeyPolicy is a key policy to follow during login.
	PrivateKeyPolicy keys.PrivateKeyPolicy
	// ProxySupportsKeyPolicyMessage lets the tsh redirector give users more
	// useful messages in the web UI if the proxy supports them.
	// TODO(atburke): DELETE in v17.0.0
	ProxySupportsKeyPolicyMessage bool
	// InitiateSSOLoginFn allows customizing issuance of SSOLoginConsoleReq. Optional.
	InitiateSSOLoginFn func(clientRedirectURL string) (redirectURL string, err error)
}

// Redirector handles SSH redirect flow with the Teleport server
type Redirector struct {
	RedirectorConfig

	server *httptest.Server
	mux    *http.ServeMux

	// ClientCallbackURL is set once the redirector's local http server
	// is running.
	ClientCallbackURL string
	// RedirectURL will be set based on the response from the Teleport
	// proxy server, will contain target redirect URL
	// to launch SSO workflow
	RedirectURL utils.SyncString

	// key is a secret key used to encode/decode
	// the data with the server, it is used so that other
	// programs running on the same computer can't easilly sniff
	// the data
	key secret.Key
	// shortPath is a link-shortener path presented to the user
	// it is used to open up the browser window, notice
	// that redirectURL will be set later
	shortPath string
	// responseC is a channel to receive responses
	responseC chan *authclient.SSHLoginResponse
	// errorC will contain errors
	errorC chan error
	// proxyURL is a URL to the Teleport Proxy
	proxyURL *url.URL
	// context is a close context
	context context.Context
	// cancel broadcasts cancel
	cancel context.CancelFunc
}

// NewRedirector returns new local web server redirector
func NewRedirector(ctx context.Context, config RedirectorConfig) (*Redirector, error) {
	// validate proxy address
	host, port, err := net.SplitHostPort(config.ProxyAddr)
	if err != nil || host == "" || port == "" {
		return nil, trace.BadParameter("'%v' is not a valid proxy address", config.ProxyAddr)
	}
	proxyAddr := "https://" + net.JoinHostPort(host, port)
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return nil, trace.BadParameter("'%v' is not a valid proxy address", proxyAddr)
	}

	// Create secret key that will be sent with the request and then used the
	// decrypt the response from the server.
	key, err := secret.NewKey()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// parse and format CallbackAddr.
	if config.CallbackAddr != "" {
		callbackURL, err := apiutils.ParseURL(config.CallbackAddr)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		// Default to HTTPS if no scheme is specified.
		// This will allow users to specify an insecure HTTP URL but
		// the backend will verify if the callback URL is allowed.
		if callbackURL.Scheme == "" {
			callbackURL.Scheme = "https"
		}
		config.CallbackAddr = callbackURL.String()
	}

	ctxCancel, cancel := context.WithCancel(ctx)
	rd := &Redirector{
		RedirectorConfig: config,
		context:          ctxCancel,
		cancel:           cancel,
		proxyURL:         proxyURL,
		mux:              http.NewServeMux(),
		key:              key,
		shortPath:        "/" + uuid.New().String(),
		responseC:        make(chan *authclient.SSHLoginResponse, 1),
		errorC:           make(chan error, 1),
	}

	// callback is a callback URL communicated to the Teleport proxy,
	// after SAML/OIDC login, the teleport will redirect user's browser
	// to this laptop-local URL
	rd.mux.Handle("/callback", rd.wrapCallback(rd.callback))
	// short path is a link-shortener style URL
	// that will redirect to the Teleport-Proxy supplied address
	rd.mux.HandleFunc(rd.shortPath, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, rd.RedirectURL.Value(), http.StatusFound)
	})

	if err := rd.startServer(); err != nil {
		return nil, trace.Wrap(err)
	}

	return rd, nil
}

// startServer starts an http server to handle the sso client callback.
func (rd *Redirector) startServer() error {
	if rd.BindAddr != "" {
		logrus.Debugf("Binding to %v.", rd.BindAddr)
		listener, err := net.Listen("tcp", rd.BindAddr)
		if err != nil {
			return trace.Wrap(err, "%v: could not bind to %v, make sure the address is host:port format for ipv4 and [ipv6]:port format for ipv6, and the address is not in use", err, rd.BindAddr)
		}
		rd.server = &httptest.Server{
			Listener: listener,
			Config: &http.Server{
				Handler:           rd.mux,
				ReadTimeout:       apidefaults.DefaultIOTimeout,
				ReadHeaderTimeout: defaults.ReadHeadersTimeout,
				WriteTimeout:      apidefaults.DefaultIOTimeout,
				IdleTimeout:       apidefaults.DefaultIdleTimeout,
			},
		}
		rd.server.Start()
	} else {
		rd.server = httptest.NewServer(rd.mux)
	}

	// Prepare callback URL.
	u, err := url.Parse(rd.baseURL() + "/callback")
	if err != nil {
		return trace.Wrap(err)
	}
	u.RawQuery = url.Values{"secret_key": {rd.key.String()}}.Encode()
	rd.ClientCallbackURL = u.String()

	return nil
}

func (rd *Redirector) SSOLoginCeremony(ctx context.Context) (*authclient.SSHLoginResponse, error) {
	if err := rd.initiate(); err != nil {
		return nil, trace.Wrap(err)
	}
	defer rd.Close()

	rd.PromptLogin()

	return rd.WaitForResponse(ctx)
}

// TODO: add prompt opts to determine whether browser is opened automatically.
func (rd *Redirector) SSOMFACeremony(ctx context.Context, requestID string, redirectURL string) (*proto.MFAAuthenticateResponse, error) {
	rd.RedirectURL.Set(redirectURL)

	rd.PromptMFA()

	resp, err := rd.WaitForResponse(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &proto.MFAAuthenticateResponse{
		Response: &proto.MFAAuthenticateResponse_SSO{
			SSO: &proto.SSOResponse{
				RequestId: requestID,
				Token:     resp.Token,
			},
		},
	}, nil
}

func (rd *Redirector) WaitForResponse(ctx context.Context) (*authclient.SSHLoginResponse, error) {
	logrus.Infof("Waiting for response at: %v.", rd.server.URL)
	select {
	case err := <-rd.ErrorC():
		log.Debugf("Got an error: %v.", err)
		return nil, trace.Wrap(err)
	case response := <-rd.ResponseC():
		log.Debugf("Got response from browser.")
		return response, nil
	case <-time.After(defaults.SSOCallbackTimeout):
		log.Debugf("Timed out waiting for callback after %v.", defaults.SSOCallbackTimeout)
		return nil, trace.Wrap(trace.Errorf("timed out waiting for callback"))
	case <-rd.Done():
		log.Debugf("Canceled by user.")
		return nil, trace.Wrap(ctx.Err(), "canceled by user")
	}
}

// initiate launches local http server on the machine,
// initiates SSO login request sequence with the Teleport Proxy
func (rd *Redirector) initiate() error {
	redirectURL, err := rd.InitiateSSOLoginFn(rd.ClientCallbackURL)
	if err != nil {
		return trace.Wrap(err)
	}

	// notice late binding of the redirect URL here, it is referenced
	// in the callback handler, but is known only after the request
	// is sent to the Teleport Proxy, that's why
	// redirectURL is a SyncString
	rd.RedirectURL.Set(redirectURL)
	return nil
}

// Done is called when redirector is closed
// or parent context is closed
func (rd *Redirector) Done() <-chan struct{} {
	return rd.context.Done()
}

// ClickableURL returns a short clickable redirect URL
func (rd *Redirector) ClickableURL() string {
	if rd.server == nil {
		return "<undefined - server is not started>"
	}
	return utils.ClickableURL(rd.baseURL() + rd.shortPath)
}

func (rd *Redirector) baseURL() string {
	if rd.CallbackAddr != "" {
		return rd.CallbackAddr
	}
	return rd.server.URL
}

// ResponseC returns a channel with response
func (rd *Redirector) ResponseC() <-chan *authclient.SSHLoginResponse {
	return rd.responseC
}

// ErrorC returns a channel with error
func (rd *Redirector) ErrorC() <-chan error {
	return rd.errorC
}

// callback is used by Teleport proxy to send back credentials
// issued by Teleport proxy
func (rd *Redirector) callback(w http.ResponseWriter, r *http.Request) (*authclient.SSHLoginResponse, error) {
	if r.URL.Path != "/callback" {
		return nil, trace.NotFound("path not found")
	}

	r.ParseForm()
	if r.Form.Has("err") {
		err := r.Form.Get("err")
		return nil, trace.Errorf("identity provider callback failed with error: %v", err)
	}

	// Decrypt ciphertext to get login response.
	plaintext, err := rd.key.Open([]byte(r.Form.Get("response")))
	if err != nil {
		return nil, trace.BadParameter("failed to decrypt response: in %v, err: %v", r.URL.String(), err)
	}

	var re authclient.SSHLoginResponse
	err = json.Unmarshal(plaintext, &re)
	if err != nil {
		return nil, trace.BadParameter("failed to decrypt response: in %v, err: %v", r.URL.String(), err)
	}

	return &re, nil
}

// Close closes redirector and releases all resources
func (rd *Redirector) Close() error {
	rd.cancel()
	if rd.server != nil {
		rd.server.Close()
	}
	return nil
}

// wrapCallback is a helper wrapper method that wraps callback HTTP handler
// and sends a result to the channel and redirect users to error page
func (rd *Redirector) wrapCallback(fn func(http.ResponseWriter, *http.Request) (*authclient.SSHLoginResponse, error)) http.Handler {
	// Generate possible redirect URLs from the proxy URL.
	clone := *rd.proxyURL
	clone.Path = LoginFailedRedirectURL
	errorURL := clone.String()
	clone.Path = LoginSuccessRedirectURL
	successURL := clone.String()
	clone.Path = LoginClose
	closeURL := clone.String()
	clone.Path = LoginTerminalRedirectURL

	connectorName := rd.ConnectorName
	if connectorName == "" {
		connectorName = rd.ConnectorID
	}
	query := clone.Query()
	// TODO: is this necessary?
	query.Set("auth", connectorName)
	clone.RawQuery = query.Encode()
	terminalRedirectURL := clone.String()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Allow", "GET, OPTIONS, POST")
		// CORS protects the _response_, and our response is always just a
		// redirect to info/login_success or error/login so it's fine to share
		// with the world; we could use the proxy URL as the origin, but that
		// would break setups where the proxy public address that tsh is using
		// is not the "main" one that ends up being used for the redirect after
		// the IdP login
		w.Header().Add("Access-Control-Allow-Origin", "*")
		switch r.Method {
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		case http.MethodOptions:
			w.WriteHeader(http.StatusOK)
			return
		case http.MethodGet, http.MethodPost:
		}

		response, err := fn(w, r)
		if err != nil {
			if trace.IsNotFound(err) {
				http.NotFound(w, r)
				return
			}
			select {
			case rd.errorC <- err:
			case <-rd.context.Done():
			}
			redirectURL := errorURL
			// A second SSO login attempt will be initiated if a key policy requirement was not satisfied.
			if requiredPolicy, err := keys.ParsePrivateKeyPolicyError(err); err == nil && rd.ProxySupportsKeyPolicyMessage {
				switch requiredPolicy {
				case keys.PrivateKeyPolicyHardwareKey, keys.PrivateKeyPolicyHardwareKeyTouch:
					// No user interaction required.
					redirectURL = closeURL
				case keys.PrivateKeyPolicyHardwareKeyPIN, keys.PrivateKeyPolicyHardwareKeyTouchAndPIN:
					// The user is prompted to enter their PIN in terminal.
					redirectURL = terminalRedirectURL
				}
			}
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		select {
		case rd.responseC <- response:
			redirectURL := successURL
			switch rd.PrivateKeyPolicy {
			case keys.PrivateKeyPolicyHardwareKey:
				// login should complete without user interaction, success.
			case keys.PrivateKeyPolicyHardwareKeyPIN:
				// The user is prompted to enter their PIN before this step,
				// so we can go straight to success screen.
			case keys.PrivateKeyPolicyHardwareKeyTouch, keys.PrivateKeyPolicyHardwareKeyTouchAndPIN:
				// The user is prompted to touch their hardware key after
				// this redirect, so display the terminal redirect screen.
				redirectURL = terminalRedirectURL
			}
			http.Redirect(w, r, redirectURL, http.StatusFound)
		case <-rd.context.Done():
			http.Redirect(w, r, errorURL, http.StatusFound)
		}
	})
}
