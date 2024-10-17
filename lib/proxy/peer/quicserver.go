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

package peer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	quicpeeringv1a "github.com/gravitational/teleport/gen/proto/go/teleport/quicpeering/v1alpha"
	"github.com/gravitational/teleport/lib/utils"
)

// QUICServerConfig holds the parameters for [NewQUICServer].
type QUICServerConfig struct {
	Log *slog.Logger
	// ClusterDialer is the dialer used to open connections to agents on behalf
	// of the peer proxies. Required.
	ClusterDialer ClusterDialer

	// CipherSuites is the set of TLS ciphersuites to be used by the server.
	//
	// Note: it won't actually have an effect, since QUIC always uses TLS 1.3,
	// and TLS 1.3 ciphersuites can't be configured in crypto/tls, but for
	// consistency's sake this should be passed along from the agent
	// configuration.
	CipherSuites []uint16
	// GetCertificate should return the server certificate at time of use. It
	// should be a certificate with the Proxy host role. Required.
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// GetClientCAs should return the certificate pool that should be used to
	// validate the client certificates of peer proxies; i.e., a pool containing
	// the trusted signers for the certificate authority of the local cluster.
	// Required.
	GetClientCAs func(*tls.ClientHelloInfo) (*x509.CertPool, error)
}

func (c *QUICServerConfig) checkAndSetDefaults() error {
	if c.Log == nil {
		c.Log = slog.Default()
	}
	c.Log = c.Log.With(
		teleport.ComponentKey,
		teleport.Component(teleport.ComponentProxy, "qpeer"),
	)

	if c.ClusterDialer == nil {
		return trace.BadParameter("missing cluster dialer")
	}

	if c.GetCertificate == nil {
		return trace.BadParameter("missing GetCertificate")
	}
	if c.GetClientCAs == nil {
		return trace.BadParameter("missing GetClientCAs")
	}

	return nil
}

// QUICServer is a proxy peering server that uses the QUIC protocol.
type QUICServer struct {
	log           *slog.Logger
	clusterDialer ClusterDialer
	tlsConfig     *tls.Config
	quicConfig    *quic.Config

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup

	replayStore replayStore

	// runCtx is a context that gets canceled when all connections should be
	// ungracefully terminated.
	runCtx context.Context
	// runCancel cancels runCtx.
	runCancel context.CancelFunc
	// serveCtx is a context that gets canceled when all listeners should stop
	// accepting new connections.
	serveCtx context.Context
	// serveCancel cancels serveCtx.
	serveCancel context.CancelFunc
}

// NewQUICServer returns a [QUICServer] with the given config.
func NewQUICServer(cfg QUICServerConfig) (*QUICServer, error) {
	if err := cfg.checkAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	tlsConfig := utils.TLSConfig(cfg.CipherSuites)
	tlsConfig.GetCertificate = cfg.GetCertificate
	tlsConfig.VerifyPeerCertificate = verifyPeerCertificateIsProxy
	tlsConfig.NextProtos = []string{quicNextProto}
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConfig.MinVersion = tls.VersionTLS13

	getClientCAs := cfg.GetClientCAs
	tlsConfig.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		clientCAs, err := getClientCAs(chi)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		utils.RefreshTLSConfigTickets(tlsConfig)
		c := tlsConfig.Clone()
		c.ClientCAs = clientCAs
		return c, nil
	}

	quicConfig := &quic.Config{
		MaxStreamReceiveWindow:     quicMaxReceiveWindow,
		MaxConnectionReceiveWindow: quicMaxReceiveWindow,

		MaxIncomingStreams:    quicMaxIncomingStreams,
		MaxIncomingUniStreams: -1,

		MaxIdleTimeout:  quicMaxIdleTimeout,
		KeepAlivePeriod: quicKeepAlivePeriod,

		Allow0RTT: true,
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	serveCtx, serveCancel := context.WithCancel(runCtx)

	return &QUICServer{
		log:           cfg.Log,
		clusterDialer: cfg.ClusterDialer,
		tlsConfig:     tlsConfig,
		quicConfig:    quicConfig,

		runCtx:      runCtx,
		runCancel:   runCancel,
		serveCtx:    serveCtx,
		serveCancel: serveCancel,
	}, nil
}

// Serve opens a listener and serves incoming connection. Returns after calling
// Close or Shutdown.
func (s *QUICServer) Serve(t *quic.Transport) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return trace.Wrap(quic.ErrServerClosed)
	}
	s.wg.Add(1)
	defer s.wg.Done()
	s.mu.Unlock()

	lis, err := t.ListenEarly(s.tlsConfig, s.quicConfig)
	if err != nil {
		return trace.Wrap(err)
	}
	defer lis.Close()
	defer context.AfterFunc(s.serveCtx, func() { _ = lis.Close() })()

	for {
		// the listener will be closed when serveCtx is done, but Accept will
		// return any queued connection before erroring out with a
		// [quic.ErrServerClosed]
		c, err := lis.Accept(context.Background())
		if err != nil {
			return trace.Wrap(err)
		}

		s.wg.Add(1)
		go s.handleConn(c)
	}
}

func (s *QUICServer) handleConn(c quic.EarlyConnection) {
	defer s.wg.Done()

	log := s.log.With(
		"remote_addr", c.RemoteAddr().String(),
		"internal_id", uuid.NewString(),
	)
	state := c.ConnectionState()
	log.InfoContext(c.Context(),
		"handling new peer connection",
		"gso", state.GSO,
		"used_0rtt", state.Used0RTT,
	)
	defer func() {
		log.DebugContext(c.Context(),
			"peer connection closed",
			"error", context.Cause(c.Context()),
		)
	}()

	defer c.CloseWithError(0, "")
	defer context.AfterFunc(s.runCtx, func() { _ = c.CloseWithError(0, "") })()

	for {
		// TODO(espadolini): stop accepting new streams once s.serveCtx is
		// canceled, once quic-go gains the ability to change the amount of
		// available streams during a connection (so we can set it to 0)
		st, err := c.AcceptStream(context.Background())
		if err != nil {
			log.DebugContext(c.Context(), "error accepting a stream", "error", err)
			return
		}

		s.wg.Add(1)
		go s.handleStream(st, c, log)
	}
}

func (s *QUICServer) handleStream(st quic.Stream, c quic.EarlyConnection, log *slog.Logger) {
	defer s.wg.Done()

	log = log.With("stream_id", st.StreamID())
	defer log.DebugContext(c.Context(), "done handling stream")

	defer st.CancelRead(0)
	defer st.CancelWrite(0)

	log.DebugContext(c.Context(), "handling stream")

	sendErr := func(toSend error) {
		st.CancelRead(0)
		defer st.CancelWrite(0)
		errBuf, err := proto.Marshal(&quicpeeringv1a.DialResponse{
			Status: status.Convert(trail.ToGRPC(toSend)).Proto(),
		})
		if err != nil {
			return
		}
		if len(errBuf) > quicMaxMessageSize {
			log.WarnContext(c.Context(), "refusing to send oversized error message (this is a bug)")
			return
		}
		st.SetWriteDeadline(time.Now().Add(quicErrorResponseTimeout))
		if _, err := st.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(errBuf)))); err != nil {
			return
		}
		if _, err := st.Write(errBuf); err != nil {
			return
		}
		if err := st.Close(); err != nil {
			return
		}
	}

	st.SetReadDeadline(time.Now().Add(quicRequestTimeout))
	var reqLen uint32
	if err := binary.Read(st, binary.LittleEndian, &reqLen); err != nil {
		log.DebugContext(c.Context(), "failed to read request size", "error", err)
		return
	}
	if reqLen >= quicMaxMessageSize {
		log.WarnContext(c.Context(), "received oversized request", "request_len", reqLen)
		return
	}
	reqBuf := make([]byte, reqLen)
	if _, err := io.ReadFull(st, reqBuf); err != nil {
		log.DebugContext(c.Context(), "failed to read request", "error", err)
		return
	}
	st.SetReadDeadline(time.Time{})

	req := new(quicpeeringv1a.DialRequest)
	if err := proto.Unmarshal(reqBuf, req); err != nil {
		log.WarnContext(c.Context(), "failed to unmarshal request", "error", err)
		return
	}

	if requestTimestamp := req.GetTimestamp().AsTime(); time.Since(requestTimestamp).Abs() > quicTimestampGraceWindow {
		log.WarnContext(c.Context(),
			"dial request has out of sync timestamp, 0-RTT performance will be impacted",
			"request_timestamp", requestTimestamp,
		)
		select {
		case <-c.HandshakeComplete():
		case <-c.Context().Done():
			return
		}
	}

	// a replayed request is always wrong even after a full handshake, the
	// replay might've happened before the legitimate request
	if !s.replayStore.add(req.GetNonce(), time.Now()) {
		log.ErrorContext(c.Context(), "request is reusing a nonce, rejecting", "nonce", req.GetNonce())
		sendErr(trace.BadParameter("reused or invalid nonce"))
		return
	}

	_, clusterName, ok := strings.Cut(req.GetTargetHostId(), ".")
	if !ok {
		sendErr(trace.BadParameter("server_id %q is missing cluster information", req.GetTargetHostId()))
		return
	}

	nodeConn, err := s.clusterDialer.Dial(clusterName, DialParams{
		From: &utils.NetAddr{
			Addr:        req.GetSource().GetAddr(),
			AddrNetwork: req.GetSource().GetNetwork(),
		},
		To: &utils.NetAddr{
			Addr:        req.GetDestination().GetAddr(),
			AddrNetwork: req.GetDestination().GetNetwork(),
		},
		ServerID: req.GetTargetHostId(),
		ConnType: types.TunnelType(req.GetConnectionType()),
	})
	if err != nil {
		sendErr(err)
		return
	}
	defer nodeConn.Close()

	var eg errgroup.Group
	eg.Go(func() error {
		defer st.Close()
		// an empty protobuf message has an empty wire encoding, so by sending a
		// size of 0 (i.e. four zero bytes) we are sending an empty DialResponse
		// with an empty Status, which signifies a successful dial
		if _, err := st.Write(binary.LittleEndian.AppendUint32(nil, 0)); err != nil {
			return trace.Wrap(err)
		}
		_, err := io.Copy(st, nodeConn)
		return trace.Wrap(err)
	})
	eg.Go(func() error {
		defer st.CancelRead(0)

		// wait for the handshake before forwarding application data from the
		// client; the client shouldn't be sending application data as 0-RTT
		// anyway, but just in case
		select {
		case <-c.HandshakeComplete():
		case <-c.Context().Done():
			return trace.Wrap(context.Cause(c.Context()))
		}

		_, err := io.Copy(nodeConn, st)
		return trace.Wrap(err)
	})
	_ = eg.Wait()
}

// Close stops listening for incoming connections and ungracefully terminates
// all the existing ones.
func (s *QUICServer) Close() error {
	s.runCancel()
	s.Shutdown(context.Background())
	return nil
}

// Shutdown stops listening for incoming connections and waits until the
// existing ones are closed or until the context expires. If the context
// expires, running connections are ungracefully terminated.
func (s *QUICServer) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	defer s.runCancel()
	defer context.AfterFunc(ctx, s.runCancel)()
	s.serveCancel()
	s.wg.Wait()
	return nil
}

// replayStore will keep track of nonces for at least twice as much time as
// [quicNoncePersistence], by storing them in a map and swapping out the map as
// needed.
type replayStore struct {
	mu   sync.Mutex
	t    time.Time
	cur  map[uint64]struct{}
	prev map[uint64]struct{}
}

func (r *replayStore) add(nonce uint64, now time.Time) (added bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Sub(r.t) > quicNoncePersistence {
		r.t = now
		r.prev, r.cur = r.cur, r.prev
		clear(r.cur)
	}
	if _, ok := r.prev[nonce]; ok {
		return false
	}
	if _, ok := r.cur[nonce]; ok {
		return false
	}
	if r.cur == nil {
		r.cur = make(map[uint64]struct{})
	}
	r.cur[nonce] = struct{}{}
	return true
}
