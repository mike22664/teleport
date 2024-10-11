// Teleport
// Copyright (C) 2024 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package peer

import (
	"time"

	"github.com/quic-go/quic-go/quicvarint"
)

const (
	quicMaxIdleTimeout  = 30 * time.Second
	quicKeepAlivePeriod = 5 * time.Second

	quicMaxReceiveWindow = quicvarint.Max

	// quicNextProto is the ALPN indicator for the current version of the QUIC
	// proxy peering protocol.
	quicNextProto = "teleport-peer-v1a"

	// quicMaxMessageSize is the maximum accepted size (in protobuf binary
	// format) for the request and response messages exchanged as part of the
	// dialing.
	quicMaxMessageSize = 128 * 1024

	// quicTimestampGraceWindow is the maximum time difference between local
	// time and reported time in a 0-RTT request. Clients should not keep trying
	// to use a request after this much time has passed.
	quicTimestampGraceWindow = time.Minute
	// quicNoncePersistence is the shortest time for which a nonce will be kept
	// in memory to prevent 0-RTT replay attacks. Should be significantly longer
	// than [quicTimestampGraceWindow]. In the current implementation, nonces
	// are kept for at least twice this value.
	quicNoncePersistence = 5 * time.Minute
)
