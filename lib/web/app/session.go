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
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/httplib/reverseproxy"
	"github.com/gravitational/teleport/lib/reversetunnelclient"
)

// session holds a request forwarder and web session for this request.
type session struct {
	// fwd can rewrite and forward requests to the target application.
	fwd *reverseproxy.Forwarder
	// ws represents the services.WebSession this requests belongs to.
	ws types.WebSession
	// transport allows to dial an application server.
	tr *transport
}

// appServerMatcher returns a Matcher function used to find which AppServer can
// handle the application requests.
func appServerMatcher(proxyClient reversetunnelclient.Tunnel, publicAddr string, clusterName string) Matcher {
	// Match healthy and PublicAddr servers. Having a list of only healthy
	// servers helps the transport fail before the request is forwarded to a
	// server (in cases where there are no healthy servers). This process might
	// take an additional time to execute, but since it is cached, only a few
	// requests need to perform it.
	return MatchAll(
		MatchPublicAddr(publicAddr),
		// NOTE: Try to leave this matcher as the last one to dial only the
		// application servers that match the requested application.
		MatchHealthy(proxyClient, clusterName),
	)
}
