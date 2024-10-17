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
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
	"github.com/quic-go/quic-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gravitational/teleport/api/types"
	apiutils "github.com/gravitational/teleport/api/utils"
	quicpeeringv1a "github.com/gravitational/teleport/gen/proto/go/teleport/quicpeering/v1alpha"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
)

func (c *Client) connectQuic(peerID string, peerAddr string) (*quicClientConn, error) {
	log := c.config.Log.WithFields(logrus.Fields{
		"peer_id":   peerID,
		"peer_addr": peerAddr,
	})
	log.Info("Setting up a QUIC client conn.")

	udpAddr, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tlsConfig := utils.TLSConfig(c.config.TLSCipherSuites)
	getCertificate := c.config.GetTLSCertificate
	tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		cert, err := getCertificate()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return cert, nil
	}
	tlsConfig.VerifyPeerCertificate = verifyPeerCertificateIsSpecificProxy(peerID + "." + c.config.ClusterName)
	tlsConfig.NextProtos = []string{quicNextProto}
	tlsConfig.ServerName = apiutils.EncodeClusterName(c.config.ClusterName)
	tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	tlsConfig.MinVersion = tls.VersionTLS13

	quicConfig := &quic.Config{
		MaxStreamReceiveWindow:     quicMaxReceiveWindow,
		MaxConnectionReceiveWindow: quicMaxReceiveWindow,

		MaxIncomingStreams:    -1,
		MaxIncomingUniStreams: -1,

		MaxIdleTimeout:  quicMaxIdleTimeout,
		KeepAlivePeriod: quicKeepAlivePeriod,

		TokenStore: quic.NewLRUTokenStore(10, 10),
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	return &quicClientConn{
		id:   peerID,
		addr: udpAddr,

		log: log,

		transport: c.config.QUICTransport,

		tlsConfig:  tlsConfig,
		getRootCAs: c.config.GetTLSRoots,
		quicConfig: quicConfig,

		runCtx:    runCtx,
		runCancel: runCancel,
	}, nil
}

type quicClientConn struct {
	id   string
	addr *net.UDPAddr

	log logrus.FieldLogger

	transport *quic.Transport

	tlsConfig  *tls.Config
	getRootCAs utils.GetRootsFunc
	quicConfig *quic.Config

	// runCtx is canceled to signal that all connections should be closed
	// (ungracefully).
	runCtx context.Context
	// runCancel cancels runCtx.
	runCancel context.CancelFunc

	mu sync.Mutex
	// closed is set at the beginning of a shutdown to signify that this client
	// conn should not be opening any new connections.
	closed bool
	// wg counts the active connections. Must only be waited after setting the
	// closed flag. Must only be potentially increased from 0 while the closed
	// flag is not set.
	wg sync.WaitGroup
}

var _ clientConn = (*quicClientConn)(nil)

// peerID implements [clientConn].
func (c *quicClientConn) peerID() string {
	return c.id
}

// peerAddr implements [clientConn].
func (c *quicClientConn) peerAddr() string {
	return c.addr.String()
}

// Close implements [clientConn].
func (c *quicClientConn) close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.runCancel()
	c.wg.Wait()
	return nil
}

// shutdown implements [clientConn].
func (c *quicClientConn) shutdown(ctx context.Context) {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	defer context.AfterFunc(ctx, c.runCancel)()
	c.wg.Wait()
}

// dial implements [clientConn].
func (c *quicClientConn) dial(nodeID string, src net.Addr, dst net.Addr, tunnelType types.TunnelType) (_ net.Conn, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, trace.ConnectionProblem(net.ErrClosed, "client is shut down")
	}
	c.wg.Add(1)
	defer c.wg.Done()
	c.mu.Unlock()

	var nonce uint64
	if err := binary.Read(rand.Reader, binary.NativeEndian, &nonce); err != nil {
		return nil, trace.Wrap(err)
	}

	log := c.log.WithField("conn_nonce", nonce)

	req := &quicpeeringv1a.DialRequest{
		ServerId: nodeID,
		ConnType: string(tunnelType),
		Source: &quicpeeringv1a.Addr{
			Network: src.Network(),
			Addr:    src.String(),
		},
		Destination: &quicpeeringv1a.Addr{
			Network: dst.Network(),
			Addr:    dst.String(),
		},
		Timestamp: timestamppb.Now(),
		Nonce:     nonce,
	}
	sizedReqBuf := make([]byte, 4, 4+proto.MarshalOptions{}.Size(req))
	sizedReqBuf, err = proto.MarshalOptions{UseCachedSize: true}.MarshalAppend(sizedReqBuf, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	binary.LittleEndian.PutUint32(sizedReqBuf, uint32(len(sizedReqBuf)-4))

	rootCAs, err := c.getRootCAs()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	utils.RefreshTLSConfigTickets(c.tlsConfig)
	tlsConfig := c.tlsConfig.Clone()
	tlsConfig.RootCAs = rootCAs

	deadline := time.Now().Add(30 * time.Second)
	dialCtx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	log.Debug("Dialing peer proxy.")
	earlyConn, err := c.transport.DialEarly(dialCtx, c.addr, tlsConfig, c.quicConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var conn quic.Connection = earlyConn
	defer func() {
		if err == nil {
			return
		}
		conn.CloseWithError(0, "")
	}()

	log.WithField("gso", conn.ConnectionState().GSO).Debug("Opened connection.")

	respBuf, stream, err := quicSendUnary(deadline, sizedReqBuf, conn)
	if err != nil {
		if !errors.Is(err, quic.Err0RTTRejected) {
			return nil, trace.Wrap(err)
		}

		log.Info("0-RTT attempt rejected, retrying with a full handshake.")
		nextConn, err := earlyConn.NextConnection(dialCtx)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		conn, earlyConn = nextConn, nil
		// NextConnection can return a valid, closed connection and no error; if
		// the connection is not closed then we completed a full handshake
		if conn.Context().Err() != nil {
			return nil, trace.Wrap(context.Cause(conn.Context()))
		}
		log.Debug("Full handshake completed after 0-RTT rejection.")
		respBuf, stream, err = quicSendUnary(deadline, sizedReqBuf, conn)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	log.WithField("used_0rtt", conn.ConnectionState().Used0RTT).Debug("Exchanged dial request and response.")

	resp := new(quicpeeringv1a.DialResponse)
	if err := proto.Unmarshal(respBuf, resp); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := trail.FromGRPC(status.FromProto(resp.GetStatus()).Err()); err != nil {
		return nil, trace.Wrap(err)
	}

	if earlyConn != nil {
		// avoid sending connection data as part of the early data; I'm not sure
		// if the client is guaranteed to be protected against replays
		// immediately after successfully receiving server data, but if it is
		// then it means that the handshake is already complete and this will
		// not block anyway
		select {
		case <-earlyConn.HandshakeComplete():
		case <-earlyConn.Context().Done():
			return nil, trace.Wrap(context.Cause(earlyConn.Context()))
		}
	}

	sc := &streamConn{
		st:   stream,
		conn: conn,

		src: src,
		dst: dst,

		log: log,
	}

	detach := context.AfterFunc(c.runCtx, func() { _ = sc.Close() })
	// conn.Context() is canceled when the connection is closed
	c.wg.Add(1)
	context.AfterFunc(conn.Context(), func() {
		log.Debug("Connection closed.")
		c.wg.Done()
		// remove the connection from the runCtx cancellation tree
		detach()
	})

	return sc, nil
}

// quicSendUnary opens a stream, sends the given request buffer and then reads a
// response buffer. Request and response are length-prefixed by a 32 bit little
// endian integer, but the buffer size is also limited by [quicMaxMessageSize].
// The given request buffer should already be length-prefixed.
func quicSendUnary(deadline time.Time, sizedReqBuf []byte, conn quic.Connection) (_ []byte, _ quic.Stream, err error) {
	stream, err := conn.OpenStream()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	defer func() {
		if err == nil {
			return
		}
		stream.CancelRead(0)
		stream.CancelWrite(0)
	}()

	stream.SetDeadline(deadline)
	if _, err := stream.Write(sizedReqBuf); err != nil {
		return nil, nil, trace.Wrap(err)
	}
	var respSize uint32
	if err := binary.Read(stream, binary.LittleEndian, &respSize); err != nil {
		return nil, nil, trace.Wrap(err)
	}
	if respSize > quicMaxMessageSize {
		return nil, nil, trace.BadParameter("oversized response message")
	}
	respBuf := make([]byte, respSize)
	if _, err := io.ReadFull(stream, respBuf); err != nil {
		return nil, nil, trace.Wrap(err)
	}
	stream.SetDeadline(time.Time{})
	return respBuf, stream, nil
}

// streamConn is a [net.Conn] using a single [quic.Stream] in a dedicated
// [quic.Connection].
type streamConn struct {
	st   quic.Stream
	conn quic.Connection

	src net.Addr
	dst net.Addr

	log logrus.FieldLogger
}

var _ net.Conn = (*streamConn)(nil)

// Read implements [net.Conn].
func (c *streamConn) Read(b []byte) (n int, err error) {
	return c.st.Read(b)
}

// Write implements [net.Conn].
func (c *streamConn) Write(b []byte) (n int, err error) {
	return c.st.Write(b)
}

// Close implements [net.Conn].
func (c *streamConn) Close() error {
	return trace.Wrap(c.conn.CloseWithError(0, ""))
}

// SetDeadline implements [net.Conn].
func (c *streamConn) SetDeadline(t time.Time) error {
	return c.st.SetDeadline(t)
}

// SetReadDeadline implements [net.Conn].
func (c *streamConn) SetReadDeadline(t time.Time) error {
	return c.st.SetReadDeadline(t)
}

// SetWriteDeadline implements [net.Conn].
func (c *streamConn) SetWriteDeadline(t time.Time) error {
	return c.st.SetWriteDeadline(t)
}

// LocalAddr implements [net.Conn].
func (c *streamConn) LocalAddr() net.Addr {
	return c.src
}

// RemoteAddr implements [net.Conn].
func (c *streamConn) RemoteAddr() net.Addr {
	return c.dst
}

type verifyPeerCertificateFunc = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

func verifyPeerCertificateIsSpecificProxy(peerID string) verifyPeerCertificateFunc {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) < 1 {
			return trace.AccessDenied("missing server certificate (this is a bug)")
		}

		clientCert := verifiedChains[0][0]
		clientIdentity, err := tlsca.FromSubject(clientCert.Subject, clientCert.NotAfter)
		if err != nil {
			return trace.Wrap(err)
		}

		if !slices.Contains(clientIdentity.Groups, string(types.RoleProxy)) {
			return trace.AccessDenied("expected Proxy server credentials")
		}

		if clientIdentity.Username != peerID {
			return trace.AccessDenied("expected proxy %v, got %q", peerID, clientIdentity.Username)
		}
		return nil
	}
}
