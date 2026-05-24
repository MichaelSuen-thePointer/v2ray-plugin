package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go"
	"github.com/v2fly/v2ray-core/v5/common/platform/filesystem"
)

const udpRelayMaxPacketSize = 65507

type udpRelayConfig struct {
	Server                    bool
	Mode                      string
	StandaloneWebSocketServer bool
	LocalAddr                 string
	LocalPort                 string
	RemoteAddr                string
	RemotePort                string
	Host                      string
	Path                      string
	TLS                       bool
	Cert                      string
	CertRaw                   string
	Key                       string
	Timeout                   time.Duration
}

type udpPacketSession interface {
	Context() context.Context
	Receive(context.Context) ([]byte, error)
	Send([]byte) error
	Close(string) error
}

type quicPacketSession struct {
	conn quic.Connection
}

func (s quicPacketSession) Context() context.Context {
	return s.conn.Context()
}

func (s quicPacketSession) Receive(ctx context.Context) ([]byte, error) {
	return s.conn.ReceiveDatagram(ctx)
}

func (s quicPacketSession) Send(payload []byte) error {
	return s.conn.SendDatagram(payload)
}

func (s quicPacketSession) Close(reason string) error {
	return s.conn.CloseWithError(0, reason)
}

type webSocketPacketSession struct {
	conn   *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
}

func newWebSocketPacketSession(parent context.Context, conn *websocket.Conn) *webSocketPacketSession {
	ctx, cancel := context.WithCancel(parent)
	conn.SetReadLimit(udpRelayMaxPacketSize)
	return &webSocketPacketSession{conn: conn, ctx: ctx, cancel: cancel}
}

func (s *webSocketPacketSession) Context() context.Context {
	return s.ctx
}

func (s *webSocketPacketSession) Receive(ctx context.Context) ([]byte, error) {
	type readResult struct {
		messageType int
		payload     []byte
		err         error
	}
	result := make(chan readResult, 1)
	go func() {
		messageType, payload, err := s.conn.ReadMessage()
		result <- readResult{messageType: messageType, payload: payload, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case r := <-result:
		if r.err != nil {
			return nil, r.err
		}
		if r.messageType != websocket.BinaryMessage {
			return nil, newError("udp websocket received non-binary message")
		}
		return r.payload, nil
	}
}

func (s *webSocketPacketSession) Send(payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.WriteMessage(websocket.BinaryMessage, payload)
}

func (s *webSocketPacketSession) Close(reason string) error {
	s.cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason), time.Now().Add(time.Second))
	return s.conn.Close()
}

type udpRelay struct {
	config udpRelayConfig

	mu          sync.Mutex
	listeners   []net.PacketConn
	quicServers []*quic.Listener
	wsServers   []*http.Server
	wsListeners []net.Listener
	closed      bool
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	clientFlows map[string]*udpClientFlow
	serverFlows map[udpPacketSession]*udpServerFlow
}

type udpClientFlow struct {
	source   net.Addr
	conn     udpPacketSession
	cancel   context.CancelFunc
	lastSeen time.Time
}

type udpServerFlow struct {
	conn     udpPacketSession
	udpConn  net.Conn
	cancel   context.CancelFunc
	lastSeen time.Time
}

func newUDPRelay(config udpRelayConfig) *udpRelay {
	return &udpRelay{config: config}
}

func newUDPRelayFromOptions() (*udpRelay, error) {
	if *udpMode == "" {
		return nil, nil
	}
	if err := validateUDPOptions(); err != nil {
		return nil, err
	}
	return newUDPRelay(udpRelayConfig{
		Server:                    *server,
		Mode:                      *udpMode,
		StandaloneWebSocketServer: *server && *udpMode == "websocket" && *mode != "websocket",
		LocalAddr:                 *localAddr,
		LocalPort:                 *localPort,
		RemoteAddr:                *remoteAddr,
		RemotePort:                *remotePort,
		Host:                      *host,
		Path:                      *udpPath,
		TLS:                       *tlsEnabled,
		Cert:                      *cert,
		CertRaw:                   *certRaw,
		Key:                       *key,
		Timeout:                   time.Duration(*udpTimeout) * time.Second,
	}), nil
}

func (r *udpRelay) Start() error {
	if r == nil {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return newError("udp relay already closed")
	}
	if len(r.listeners) > 0 || len(r.wsListeners) > 0 {
		return nil
	}

	r.ctx, r.cancel = context.WithCancel(context.Background())
	if !r.config.Server {
		r.clientFlows = make(map[string]*udpClientFlow)
	} else {
		r.serverFlows = make(map[udpPacketSession]*udpServerFlow)
	}
	r.wg.Add(1)
	go r.cleanupIdleFlows()
	if r.config.Server && r.config.Mode == "websocket" {
		if r.config.StandaloneWebSocketServer {
			if err := r.startServerWebSocketListenersLocked(); err != nil {
				return r.cleanupFailedStartLocked(err)
			}
		}
		return nil
	}

	for _, addr := range parseLocalAddr(r.config.LocalAddr) {
		listenAddr := net.JoinHostPort(addr, r.config.LocalPort)
		conn, err := net.ListenPacket("udp", listenAddr)
		if err != nil {
			return r.cleanupFailedStartLocked(newError("failed to start udp relay at", listenAddr).Base(err))
		}
		r.listeners = append(r.listeners, conn)
		if r.config.Server {
			server, err := quic.Listen(conn, r.serverTLSConfig(), r.quicConfig())
			if err != nil {
				return r.cleanupFailedStartLocked(newError("failed to start udp quic relay at", listenAddr).Base(err))
			}
			r.quicServers = append(r.quicServers, server)
			r.wg.Add(1)
			go r.serveServerQUIC(server)
		} else {
			r.wg.Add(1)
			go r.serveClientUDP(conn)
		}
	}

	return nil
}

func (r *udpRelay) cleanupFailedStartLocked(startErr error) error {
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	for _, quicServer := range r.quicServers {
		if err := quicServer.Close(); err != nil {
			logWarn(err.Error())
		}
	}
	r.quicServers = nil
	r.closeServerWebSocketListenersLocked()
	for _, listener := range r.listeners {
		if err := listener.Close(); err != nil {
			logWarn(err.Error())
		}
	}
	r.listeners = nil
	return startErr
}

func (r *udpRelay) serveServerQUIC(server *quic.Listener) {
	defer r.wg.Done()

	for {
		conn, err := server.Accept(r.ctx)
		if err != nil {
			if r.isClosed() {
				return
			}
			logWarn("udp quic accept failed:", err.Error())
			continue
		}
		if err := r.startServerFlow(quicPacketSession{conn: conn}); err != nil {
			logWarn("failed to start udp server flow:", err.Error())
			if closeErr := conn.CloseWithError(0, "udp server flow failed"); closeErr != nil {
				logWarn(closeErr.Error())
			}
		}
	}
}

func (r *udpRelay) startServerWebSocketListenersLocked() error {
	for _, addr := range parseLocalAddr(r.config.LocalAddr) {
		listenAddr := net.JoinHostPort(addr, r.config.LocalPort)
		listener, err := net.Listen("tcp", listenAddr)
		if err != nil {
			r.closeServerWebSocketListenersLocked()
			return newError("failed to start udp websocket relay at", listenAddr).Base(err)
		}
		if r.config.TLS {
			certificate, err := r.serverWebSocketTLSCertificate()
			if err != nil {
				listener.Close()
				r.closeServerWebSocketListenersLocked()
				return newError("failed to load udp websocket relay certificate").Base(err)
			}
			listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}})
		}
		server := &http.Server{Handler: http.HandlerFunc(r.serveStandaloneWebSocket)}
		r.wsListeners = append(r.wsListeners, listener)
		r.wsServers = append(r.wsServers, server)
		r.wg.Add(1)
		go func(s *http.Server, l net.Listener) {
			defer r.wg.Done()
			if err := s.Serve(l); err != nil && err != http.ErrServerClosed && !r.isClosed() {
				logWarn("udp websocket relay serve failed:", err.Error())
			}
		}(server, listener)
	}
	return nil
}

func (r *udpRelay) serveStandaloneWebSocket(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != r.config.Path {
		http.NotFound(w, req)
		return
	}
	r.ServeWebSocket(w, req)
}

func (r *udpRelay) startServerFlow(conn udpPacketSession) error {
	ctx, cancel := context.WithCancel(r.ctx)
	remoteAddr := net.JoinHostPort(r.config.RemoteAddr, r.config.RemotePort)
	udpConn, err := (&net.Dialer{}).DialContext(ctx, "udp", remoteAddr)
	if err != nil {
		cancel()
		return err
	}

	flow := &udpServerFlow{
		conn:     conn,
		udpConn:  udpConn,
		cancel:   cancel,
		lastSeen: time.Now(),
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		cancel()
		if err := udpConn.Close(); err != nil {
			logWarn(err.Error())
		}
		return newError("udp relay closed")
	}
	r.serverFlows[conn] = flow
	r.wg.Add(2)
	go r.forwardServerQUICToUDP(flow)
	go r.forwardServerUDPToQUIC(flow)
	r.mu.Unlock()

	return nil
}

func (r *udpRelay) forwardServerQUICToUDP(flow *udpServerFlow) {
	defer r.wg.Done()

	for {
		payload, err := flow.conn.Receive(flow.conn.Context())
		if err != nil {
			if !r.isClosed() {
				logWarn("udp server flow quic receive failed:", err.Error())
			}
			r.closeServerFlow(flow)
			return
		}
		if len(payload) == 0 {
			continue
		}
		if _, err := flow.udpConn.Write(payload); err != nil {
			if !r.isClosed() {
				logWarn("failed to forward udp datagram to ss-server:", err.Error())
			}
			r.closeServerFlow(flow)
			return
		}
		r.touchServerFlow(flow)
	}
}

func (r *udpRelay) forwardServerUDPToQUIC(flow *udpServerFlow) {
	defer r.wg.Done()

	buf := make([]byte, udpRelayMaxPacketSize)
	for {
		n, err := flow.udpConn.Read(buf)
		if err != nil {
			if !r.isClosed() {
				logWarn("udp server flow socket read failed:", err.Error())
			}
			r.closeServerFlow(flow)
			return
		}
		if n == 0 {
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		if err := flow.conn.Send(payload); err != nil {
			var tooLarge *quic.DatagramTooLargeError
			if errors.As(err, &tooLarge) {
				logWarn("drop oversized udp response datagram max", tooLarge.MaxDatagramPayloadSize)
				continue
			}
			if !r.isClosed() {
				logWarn("failed to send udp response datagram:", err.Error())
			}
			r.closeServerFlow(flow)
			return
		}
		r.touchServerFlow(flow)
	}
}

func (r *udpRelay) cleanupIdleFlows() {
	defer r.wg.Done()

	interval := r.config.Timeout / 2
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case now := <-ticker.C:
			r.expireIdleFlows(now)
		}
	}
}

func (r *udpRelay) expireIdleFlows(now time.Time) {
	var clientFlows []*udpClientFlow
	var serverFlows []*udpServerFlow

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	for key, flow := range r.clientFlows {
		if now.Sub(flow.lastSeen) >= r.config.Timeout {
			delete(r.clientFlows, key)
			clientFlows = append(clientFlows, flow)
		}
	}
	for conn, flow := range r.serverFlows {
		if now.Sub(flow.lastSeen) >= r.config.Timeout {
			delete(r.serverFlows, conn)
			serverFlows = append(serverFlows, flow)
		}
	}
	r.mu.Unlock()

	for _, flow := range clientFlows {
		flow.cancel()
		if err := flow.conn.Close("udp flow idle timeout"); err != nil && !r.isClosed() {
			logWarn(err.Error())
		}
	}
	for _, flow := range serverFlows {
		r.shutdownServerFlow(flow, "udp flow idle timeout")
	}
}

func (r *udpRelay) serveClientUDP(listener net.PacketConn) {
	defer r.wg.Done()

	buf := make([]byte, udpRelayMaxPacketSize)
	for {
		n, source, err := listener.ReadFrom(buf)
		if err != nil {
			if r.isClosed() {
				return
			}
			logWarn("udp relay read failed:", err.Error())
			continue
		}
		if n == 0 {
			continue
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])

		flow, err := r.getClientFlow(listener, source)
		if err != nil {
			if !r.isClosed() {
				logWarn("failed to create udp client flow:", err.Error())
			}
			continue
		}
		r.touchClientFlow(source.String())

		if err := flow.conn.Send(payload); err != nil {
			var tooLarge *quic.DatagramTooLargeError
			if errors.As(err, &tooLarge) {
				logWarn("drop oversized udp datagram from", source.String(), "max", tooLarge.MaxDatagramPayloadSize)
				continue
			}
			logWarn("failed to send udp datagram:", err.Error())
		}
	}
}

func (r *udpRelay) getClientFlow(listener net.PacketConn, source net.Addr) (*udpClientFlow, error) {
	key := source.String()

	r.mu.Lock()
	if flow := r.clientFlows[key]; flow != nil {
		r.mu.Unlock()
		return flow, nil
	}
	ctx := r.ctx
	r.mu.Unlock()

	flowCtx, cancel := context.WithCancel(ctx)
	remoteAddr := net.JoinHostPort(r.config.RemoteAddr, r.config.RemotePort)
	conn, err := r.dialClientSession(flowCtx, remoteAddr)
	if err != nil {
		cancel()
		return nil, err
	}

	flow := &udpClientFlow{
		source:   source,
		conn:     conn,
		cancel:   cancel,
		lastSeen: time.Now(),
	}

	r.mu.Lock()
	if existing := r.clientFlows[key]; existing != nil {
		r.mu.Unlock()
		cancel()
		if err := conn.Close("duplicate udp flow"); err != nil {
			logWarn(err.Error())
		}
		return existing, nil
	}
	if r.closed {
		r.mu.Unlock()
		cancel()
		if err := conn.Close("udp relay closed"); err != nil {
			logWarn(err.Error())
		}
		return nil, newError("udp relay closed")
	}
	r.clientFlows[key] = flow
	r.wg.Add(1)
	go r.receiveClientDatagrams(listener, key, flow)
	r.mu.Unlock()

	return flow, nil
}

func (r *udpRelay) receiveClientDatagrams(listener net.PacketConn, key string, flow *udpClientFlow) {
	defer r.wg.Done()

	for {
		payload, err := flow.conn.Receive(flow.conn.Context())
		if err != nil {
			if !r.isClosed() {
				logWarn("udp client flow receive failed:", err.Error())
			}
			r.removeClientFlow(key, flow)
			return
		}
		if len(payload) == 0 {
			continue
		}
		if _, err := listener.WriteTo(payload, flow.source); err != nil {
			if !r.isClosed() {
				logWarn("failed to write udp datagram to local endpoint:", err.Error())
			}
			continue
		}
		r.touchClientFlow(key)
	}
}

func (r *udpRelay) clientTLSConfig() *tls.Config {
	config := &tls.Config{
		ServerName: r.config.Host,
		NextProtos: []string{
			"v2ray-plugin-sip003u",
		},
	}
	if r.config.Cert == "" && r.config.CertRaw == "" {
		return config
	}

	certPEM, err := r.readConfiguredCertificate(r.config.Cert)
	if err != nil {
		logWarn("failed to read udp relay certificate:", err.Error())
		return config
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		logWarn("failed to parse udp relay certificate authority")
		return config
	}
	config.RootCAs = roots
	return config
}

func (r *udpRelay) dialClientSession(ctx context.Context, remoteAddr string) (udpPacketSession, error) {
	if r.config.Mode == "websocket" {
		scheme := "ws"
		dialer := websocket.Dialer{}
		if r.config.TLS {
			scheme = "wss"
			dialer.TLSClientConfig = r.webSocketClientTLSConfig()
		} else if r.config.Cert != "" || r.config.CertRaw != "" {
			dialer.TLSClientConfig = r.webSocketClientTLSConfig()
		}
		u := url.URL{Scheme: scheme, Host: remoteAddr, Path: r.config.Path}
		header := http.Header{}
		if r.config.Host != "" {
			header.Set("Host", r.config.Host)
		}
		conn, _, err := dialer.DialContext(ctx, u.String(), header)
		if err != nil {
			return nil, err
		}
		return newWebSocketPacketSession(ctx, conn), nil
	}

	conn, err := quic.DialAddr(ctx, remoteAddr, r.clientTLSConfig(), r.quicConfig())
	if err != nil {
		return nil, err
	}
	return quicPacketSession{conn: conn}, nil
}

func (r *udpRelay) webSocketClientTLSConfig() *tls.Config {
	config := &tls.Config{ServerName: r.config.Host}
	if r.config.Cert == "" && r.config.CertRaw == "" {
		return config
	}
	certPEM, err := r.readConfiguredCertificate(r.config.Cert)
	if err != nil {
		logWarn("failed to read udp websocket certificate:", err.Error())
		return config
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		logWarn("failed to parse udp websocket certificate authority")
		return config
	}
	config.RootCAs = roots
	return config
}

func (r *udpRelay) ServeWebSocket(w http.ResponseWriter, req *http.Request) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	conn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		logWarn("udp websocket upgrade failed:", err.Error())
		return
	}
	session := newWebSocketPacketSession(r.ctx, conn)
	if err := r.startServerFlow(session); err != nil {
		logWarn("failed to start udp websocket server flow:", err.Error())
		if closeErr := session.Close("udp websocket server flow failed"); closeErr != nil {
			logWarn(closeErr.Error())
		}
	}
}

func (r *udpRelay) serverTLSConfig() *tls.Config {
	certificate, err := r.serverTLSCertificate()
	if err != nil {
		logWarn("failed to load udp relay server certificate:", err.Error())
		return &tls.Config{
			NextProtos: []string{"v2ray-plugin-sip003u"},
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"v2ray-plugin-sip003u"},
	}
}

func (r *udpRelay) serverTLSCertificate() (tls.Certificate, error) {
	certPath := r.config.Cert
	keyPath := r.config.Key
	if certPath == "" && r.config.CertRaw == "" {
		certPath = fmt.Sprintf("%s/.acme.sh/%s/fullchain.cer", homeDir(), r.config.Host)
		logWarn("No UDP TLS cert specified, trying", certPath)
	}
	certPEM, err := r.readConfiguredCertificate(certPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	if keyPath == "" {
		keyPath = fmt.Sprintf("%[1]s/.acme.sh/%[2]s/%[2]s.key", homeDir(), r.config.Host)
		logWarn("No UDP TLS key specified, trying", keyPath)
	}
	keyPEM, err := filesystem.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func (r *udpRelay) serverWebSocketTLSCertificate() (tls.Certificate, error) {
	certPath := r.config.Cert
	keyPath := r.config.Key
	if certPath == "" && r.config.CertRaw == "" {
		certPath = fmt.Sprintf("%s/.acme.sh/%s/fullchain.cer", homeDir(), r.config.Host)
		logWarn("No UDP WebSocket TLS cert specified, trying", certPath)
	}
	certPEM, err := r.readConfiguredCertificate(certPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	if keyPath == "" {
		keyPath = fmt.Sprintf("%[1]s/.acme.sh/%[2]s/%[2]s.key", homeDir(), r.config.Host)
		logWarn("No UDP WebSocket TLS key specified, trying", keyPath)
	}
	keyPEM, err := filesystem.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func (r *udpRelay) readConfiguredCertificate(certPath string) ([]byte, error) {
	if certPath != "" {
		return filesystem.ReadFile(certPath)
	}
	if r.config.CertRaw != "" {
		certHead := "-----BEGIN CERTIFICATE-----"
		certTail := "-----END CERTIFICATE-----"
		fixedCert := certHead + "\n" + r.config.CertRaw + "\n" + certTail
		return []byte(fixedCert), nil
	}
	return nil, newError("missing udp relay certificate")
}

func (r *udpRelay) quicConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  r.config.Timeout,
		KeepAlivePeriod: r.config.Timeout / 2,
	}
}

func (r *udpRelay) touchServerFlow(flow *udpServerFlow) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.serverFlows[flow.conn] == flow {
		flow.lastSeen = time.Now()
	}
}

func (r *udpRelay) closeServerFlow(flow *udpServerFlow) {
	r.mu.Lock()
	if r.serverFlows[flow.conn] == flow {
		delete(r.serverFlows, flow.conn)
	}
	r.mu.Unlock()

	r.shutdownServerFlow(flow, "udp server flow closed")
}

func (r *udpRelay) shutdownServerFlow(flow *udpServerFlow, reason string) {
	flow.cancel()
	if err := flow.udpConn.Close(); err != nil && !r.isClosed() {
		logWarn(err.Error())
	}
	if err := flow.conn.Close(reason); err != nil && !r.isClosed() {
		logWarn(err.Error())
	}
}

func (r *udpRelay) touchClientFlow(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if flow := r.clientFlows[key]; flow != nil {
		flow.lastSeen = time.Now()
	}
}

func (r *udpRelay) removeClientFlow(key string, flow *udpClientFlow) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.clientFlows[key] == flow {
		delete(r.clientFlows, key)
	}
}

func (r *udpRelay) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func (r *udpRelay) Close() error {
	if r == nil {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true
	if r.cancel != nil {
		r.cancel()
	}

	var closeErr error
	for _, quicServer := range r.quicServers {
		if err := quicServer.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	r.quicServers = nil

	r.closeServerWebSocketListenersLocked()

	for _, listener := range r.listeners {
		if err := listener.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	r.listeners = nil

	for key, flow := range r.clientFlows {
		flow.cancel()
		if err := flow.conn.Close("udp relay closed"); err != nil && closeErr == nil {
			closeErr = err
		}
		delete(r.clientFlows, key)
	}
	for conn, flow := range r.serverFlows {
		flow.cancel()
		if err := flow.udpConn.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
		if err := conn.Close("udp relay closed"); err != nil && closeErr == nil {
			closeErr = err
		}
		delete(r.serverFlows, conn)
	}
	r.mu.Unlock()
	r.wg.Wait()
	r.mu.Lock()

	return closeErr
}

func (r *udpRelay) closeServerWebSocketListenersLocked() {
	for _, server := range r.wsServers {
		if err := server.Close(); err != nil {
			logWarn(err.Error())
		}
	}
	r.wsServers = nil
	for _, listener := range r.wsListeners {
		if err := listener.Close(); err != nil {
			logWarn(err.Error())
		}
	}
	r.wsListeners = nil
}
