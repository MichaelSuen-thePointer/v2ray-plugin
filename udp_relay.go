package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/v2fly/v2ray-core/v5/common/platform/filesystem"
)

const udpRelayMaxPacketSize = 65507

type udpRelayConfig struct {
	Server     bool
	LocalAddr  string
	LocalPort  string
	RemoteAddr string
	RemotePort string
	Host       string
	Cert       string
	CertRaw    string
	Key        string
	Timeout    time.Duration
}

type udpRelay struct {
	config udpRelayConfig

	mu          sync.Mutex
	listeners   []net.PacketConn
	quicServers []*quic.Listener
	closed      bool
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	clientFlows map[string]*udpClientFlow
	serverFlows map[quic.Connection]*udpServerFlow
}

type udpClientFlow struct {
	source   net.Addr
	conn     quic.Connection
	cancel   context.CancelFunc
	lastSeen time.Time
}

type udpServerFlow struct {
	conn     quic.Connection
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
		Server:     *server,
		LocalAddr:  *localAddr,
		LocalPort:  *localPort,
		RemoteAddr: *remoteAddr,
		RemotePort: *remotePort,
		Host:       *host,
		Cert:       *cert,
		CertRaw:    *certRaw,
		Key:        *key,
		Timeout:    time.Duration(*udpTimeout) * time.Second,
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
	if len(r.listeners) > 0 {
		return nil
	}

	r.ctx, r.cancel = context.WithCancel(context.Background())
	if !r.config.Server {
		r.clientFlows = make(map[string]*udpClientFlow)
	} else {
		r.serverFlows = make(map[quic.Connection]*udpServerFlow)
	}
	r.wg.Add(1)
	go r.cleanupIdleFlows()

	for _, addr := range parseLocalAddr(r.config.LocalAddr) {
		listenAddr := net.JoinHostPort(addr, r.config.LocalPort)
		conn, err := net.ListenPacket("udp", listenAddr)
		if err != nil {
			for _, listener := range r.listeners {
				if closeErr := listener.Close(); closeErr != nil {
					logWarn(closeErr.Error())
				}
			}
			r.listeners = nil
			return newError("failed to start udp relay at", listenAddr).Base(err)
		}
		r.listeners = append(r.listeners, conn)
		if r.config.Server {
			server, err := quic.Listen(conn, r.serverTLSConfig(), r.quicConfig())
			if err != nil {
				for _, quicServer := range r.quicServers {
					if closeErr := quicServer.Close(); closeErr != nil {
						logWarn(closeErr.Error())
					}
				}
				for _, listener := range r.listeners {
					if closeErr := listener.Close(); closeErr != nil {
						logWarn(closeErr.Error())
					}
				}
				r.quicServers = nil
				r.listeners = nil
				return newError("failed to start udp quic relay at", listenAddr).Base(err)
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
		if err := r.startServerFlow(conn); err != nil {
			logWarn("failed to start udp server flow:", err.Error())
			if closeErr := conn.CloseWithError(0, "udp server flow failed"); closeErr != nil {
				logWarn(closeErr.Error())
			}
		}
	}
}

func (r *udpRelay) startServerFlow(conn quic.Connection) error {
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
		payload, err := flow.conn.ReceiveDatagram(flow.conn.Context())
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
		if err := flow.conn.SendDatagram(payload); err != nil {
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
		if err := flow.conn.CloseWithError(0, "udp flow idle timeout"); err != nil && !r.isClosed() {
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

		if err := flow.conn.SendDatagram(payload); err != nil {
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
	conn, err := quic.DialAddr(flowCtx, remoteAddr, r.clientTLSConfig(), r.quicConfig())
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
		if err := conn.CloseWithError(0, "duplicate udp flow"); err != nil {
			logWarn(err.Error())
		}
		return existing, nil
	}
	if r.closed {
		r.mu.Unlock()
		cancel()
		if err := conn.CloseWithError(0, "udp relay closed"); err != nil {
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
		payload, err := flow.conn.ReceiveDatagram(flow.conn.Context())
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
	if err := flow.conn.CloseWithError(0, reason); err != nil && !r.isClosed() {
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

	for _, listener := range r.listeners {
		if err := listener.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	r.listeners = nil

	for key, flow := range r.clientFlows {
		flow.cancel()
		if err := flow.conn.CloseWithError(0, "udp relay closed"); err != nil && closeErr == nil {
			closeErr = err
		}
		delete(r.clientFlows, key)
	}
	for conn, flow := range r.serverFlows {
		flow.cancel()
		if err := flow.udpConn.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
		if err := conn.CloseWithError(0, "udp relay closed"); err != nil && closeErr == nil {
			closeErr = err
		}
		delete(r.serverFlows, conn)
	}
	r.mu.Unlock()
	r.wg.Wait()
	r.mu.Lock()

	return closeErr
}
