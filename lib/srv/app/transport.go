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

package app

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"slices"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/lib"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/app/common"
	"github.com/gravitational/teleport/lib/utils"
)

// transportConfig is configuration for a rewriting transport.
type transportConfig struct {
	app          types.Application
	publicPort   string
	cipherSuites []uint16
	jwt          string
	traits       wrappers.Traits
	log          *slog.Logger
}

// Check validates configuration.
func (c *transportConfig) Check() error {
	if c.app == nil {
		return trace.BadParameter("app missing")
	}
	if c.publicPort == "" {
		return trace.BadParameter("public port missing")
	}
	if c.jwt == "" {
		return trace.BadParameter("jwt missing")
	}
	if c.log == nil {
		c.log = slog.Default().With(teleport.ComponentKey, "transport")
	}

	return nil
}

// transport is a rewriting http.RoundTripper that can audit and forward
// requests to an internal application.
type transport struct {
	closeContext context.Context

	*transportConfig

	tr http.RoundTripper

	uri *url.URL
}

// newTransport creates a new transport.
func newTransport(ctx context.Context, c *transportConfig) (*transport, error) {
	if err := c.Check(); err != nil {
		return nil, trace.Wrap(err)
	}

	// Parse the target address once then inject it into all requests.
	uri, err := url.Parse(c.app.GetURI())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Clone and configure the transport.
	tr, err := defaults.Transport()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tr.TLSClientConfig, err = configureTLS(c)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &transport{
		closeContext:    ctx,
		transportConfig: c,
		uri:             uri,
		tr:              tr,
	}, nil
}

// RoundTrip will rewrite the request, forward the request to the target
// application, emit an event to the audit log, then rewrite the response.
func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Check if the request path needs re-writing. This occurs when the URI
	// contains a path like http://localhost:8080/app/acme, but the request comes
	// to https://publicAddr. In that case do a 302 to the correct path instead
	// of doing path re-writing on all requests. This is a workaround to make
	// sure Teleport does not break SPA.
	if location, ok := t.needsPathRedirect(r); ok {
		return &http.Response{
			Status:     http.StatusText(http.StatusFound),
			StatusCode: http.StatusFound,
			Proto:      r.Proto,
			ProtoMajor: r.ProtoMajor,
			ProtoMinor: r.ProtoMinor,
			Body:       http.NoBody,
			Header: http.Header{
				"Location": []string{location},
			},
			TLS: r.TLS,
		}, nil
	}

	// Perform any request rewriting needed before forwarding the request.
	if err := t.rewriteRequest(r); err != nil {
		return nil, trace.Wrap(err)
	}

	sessCtx, err := common.GetSessionContext(r)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Forward the request to the target application and emit an audit event.
	resp, err := t.tr.RoundTrip(r)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	status := uint32(resp.StatusCode)

	// Emit the event to the audit log.
	if err := sessCtx.Audit.OnRequest(t.closeContext, sessCtx, r, status, nil /*aws endpoint*/); err != nil {
		return nil, trace.Wrap(err)
	}

	// Perform any response rewriting needed before returning the request.
	if err := t.rewriteResponse(resp); err != nil {
		return nil, trace.Wrap(err)
	}

	return resp, nil
}

// rewriteRequest applies any rewriting rules to the request before it's forwarded.
func (t *transport) rewriteRequest(r *http.Request) error {
	// Update the target address of the request so it's forwarded correctly.
	r.URL.Scheme = t.uri.Scheme
	r.URL.Host = t.uri.Host

	// Add headers from rewrite configuration.
	rewriteHeaders(r, t.transportConfig)

	return nil
}

// rewriteHeaders applies headers rewrites from the application configuration.
func rewriteHeaders(r *http.Request, c *transportConfig) {
	// Add in JWT headers.
	r.Header.Set(teleport.AppJWTHeader, c.jwt)

	if c.app.GetRewrite() == nil || len(c.app.GetRewrite().Headers) == 0 {
		return
	}
	for _, header := range c.app.GetRewrite().Headers {
		if common.IsReservedHeader(header.Name) {
			c.log.With("header_name", header.Name).DebugContext(context.Background(), "Not rewriting Teleport reserved header")
			continue
		}
		values, err := services.ApplyValueTraits(header.Value, c.traits)
		if err != nil {
			c.log.With(
				"header_value", header.Value,
				"error", err,
			).DebugContext(context.Background(), "Failed to apply traits")
			continue
		}
		r.Header.Del(header.Name)
		for _, value := range values {
			switch http.CanonicalHeaderKey(header.Name) {
			case teleport.HostHeader:
				r.Host = value
			default:
				r.Header.Add(header.Name, value)
			}
		}
	}
}

// needsPathRedirect checks if the request should be redirected to a different path.
// At the moment, the only time a redirect happens is if URI specified is not
// "/" and the public address being requested is "/".
func (t *transport) needsPathRedirect(r *http.Request) (string, bool) {
	// If the URI for the application has no path specified, nothing to be done.
	uriPath := path.Clean(t.uri.Path)
	if uriPath == "." {
		uriPath = "/"
	}
	if uriPath == "/" {
		return "", false
	}

	// For simplicity, only support redirecting to the URI path if the root path
	// is requested.
	reqPath := path.Clean(r.URL.Path)
	if reqPath == "." {
		reqPath = "/"
	}
	if reqPath != "/" {
		return "", false
	}

	u := url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(t.app.GetPublicAddr(), t.publicPort),
		Path:   uriPath,
	}
	return u.String(), true
}

// rewriteResponse applies any rewriting rules to the response before returning it.
func (t *transport) rewriteResponse(resp *http.Response) error {
	switch {
	case t.app.GetRewrite() != nil && len(t.app.GetRewrite().Redirect) > 0:
		err := t.rewriteRedirect(resp)
		if err != nil {
			return trace.Wrap(err)
		}
	default:
	}
	return nil
}

// rewriteRedirect applies redirect rules to the response.
func (t *transport) rewriteRedirect(resp *http.Response) error {
	if utils.IsRedirect(resp.StatusCode) {
		// Parse the "Location" header.
		u, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			return trace.Wrap(err)
		}

		// If the redirect location is one of the hosts specified in the list of
		// redirects, rewrite the header.
		if slices.Contains(t.app.GetRewrite().Redirect, host(u.Host)) {
			u.Scheme = "https"
			u.Host = net.JoinHostPort(t.app.GetPublicAddr(), t.publicPort)
		}
		resp.Header.Set("Location", u.String())
	}
	return nil
}

// configureTLS creates and configures a *tls.Config that will be used for
// mutual authentication.
func configureTLS(c *transportConfig) (*tls.Config, error) {
	tlsConfig := utils.TLSConfig(c.cipherSuites)

	// Don't verify the server's certificate if Teleport was started with
	// the --insecure flag, or 'insecure_skip_verify' was specifically requested in
	// the application config.
	tlsConfig.InsecureSkipVerify = (lib.IsInsecureDevMode() || c.app.GetInsecureSkipVerify())

	return tlsConfig, nil
}

// host returns the host from a host:port string.
func host(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
