package main

import (
	"context"
	gotls "crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"time"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common/platform/filesystem"
)

type webSocketRouterConfig struct {
	LocalAddr    string
	LocalPort    string
	TCPPath      string
	UDPPath      string
	InternalAddr string
	InternalPort string
	TLS          bool
	Host         string
	Cert         string
	CertRaw      string
	Key          string
}

type webSocketRouter struct {
	config    webSocketRouterConfig
	udpRelay  *udpRelay
	proxy     *httputil.ReverseProxy
	servers   []*http.Server
	listeners []net.Listener
	wg        sync.WaitGroup
}

func newWebSocketRouter(config webSocketRouterConfig, udpRelay *udpRelay) (*webSocketRouter, error) {
	target := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(config.InternalAddr, config.InternalPort),
	}
	return &webSocketRouter{
		config:   config,
		udpRelay: udpRelay,
		proxy:    httputil.NewSingleHostReverseProxy(target),
	}, nil
}

func (r *webSocketRouter) Start() error {
	for _, addr := range parseLocalAddr(r.config.LocalAddr) {
		listenAddr := net.JoinHostPort(addr, r.config.LocalPort)
		listener, err := net.Listen("tcp", listenAddr)
		if err != nil {
			r.Close()
			return newError("failed to start websocket router at", listenAddr).Base(err)
		}
		if r.config.TLS {
			cert, err := r.tlsCertificate()
			if err != nil {
				listener.Close()
				r.Close()
				return newError("failed to load websocket router certificate").Base(err)
			}
			listener = gotls.NewListener(listener, &gotls.Config{Certificates: []gotls.Certificate{cert}})
		}

		server := &http.Server{Handler: http.HandlerFunc(r.serveHTTP)}
		r.listeners = append(r.listeners, listener)
		r.servers = append(r.servers, server)
		r.wg.Add(1)
		go func(s *http.Server, l net.Listener) {
			defer r.wg.Done()
			if err := s.Serve(l); err != nil && err != http.ErrServerClosed {
				logWarn("websocket router serve failed:", err.Error())
			}
		}(server, listener)
	}
	return nil
}

func (r *webSocketRouter) serveHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case r.config.UDPPath:
		r.udpRelay.ServeWebSocket(w, req)
	case r.config.TCPPath:
		r.proxy.ServeHTTP(w, req)
	default:
		http.NotFound(w, req)
	}
}

func (r *webSocketRouter) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var closeErr error
	for _, server := range r.servers {
		if err := server.Shutdown(ctx); err != nil && err != http.ErrServerClosed && closeErr == nil {
			closeErr = err
		}
	}
	for _, listener := range r.listeners {
		if err := listener.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	r.wg.Wait()
	return closeErr
}

func (r *webSocketRouter) tlsCertificate() (gotls.Certificate, error) {
	certPath := r.config.Cert
	keyPath := r.config.Key
	if certPath == "" && r.config.CertRaw == "" {
		certPath = fmt.Sprintf("%s/.acme.sh/%s/fullchain.cer", homeDir(), r.config.Host)
		logWarn("No TLS cert specified, trying", certPath)
	}
	certPEM, err := readRouterCertificate(certPath, r.config.CertRaw)
	if err != nil {
		return gotls.Certificate{}, err
	}
	if keyPath == "" {
		keyPath = fmt.Sprintf("%[1]s/.acme.sh/%[2]s/%[2]s.key", homeDir(), r.config.Host)
		logWarn("No TLS key specified, trying", keyPath)
	}
	keyPEM, err := filesystem.ReadFile(keyPath)
	if err != nil {
		return gotls.Certificate{}, err
	}
	return gotls.X509KeyPair(certPEM, keyPEM)
}

func readRouterCertificate(certPath, certRaw string) ([]byte, error) {
	if certPath != "" {
		return filesystem.ReadFile(certPath)
	}
	if certRaw != "" {
		return []byte("-----BEGIN CERTIFICATE-----\n" + certRaw + "\n-----END CERTIFICATE-----"), nil
	}
	return nil, newError("missing websocket router certificate")
}

func startCombinedWebSocketServer() (core.Server, error) {
	internalPort, err := allocateLoopbackTCPPort()
	if err != nil {
		return nil, err
	}

	publicLocalAddr := *localAddr
	publicLocalPort := *localPort
	oldLocalAddr := *localAddr
	oldLocalPort := *localPort
	oldTLSEnabled := *tlsEnabled
	*localAddr = "127.0.0.1"
	*localPort = internalPort
	*tlsEnabled = false
	config, err := generateConfig()
	*localAddr = oldLocalAddr
	*localPort = oldLocalPort
	*tlsEnabled = oldTLSEnabled
	if err != nil {
		return nil, newError("failed to parse internal websocket config").Base(err)
	}

	instance, err := core.New(config)
	if err != nil {
		return nil, newError("failed to create internal v2ray instance").Base(err)
	}
	udpRelay, err := newUDPRelayFromOptions()
	if err != nil {
		return nil, err
	}
	router, err := newWebSocketRouter(webSocketRouterConfig{
		LocalAddr:    publicLocalAddr,
		LocalPort:    publicLocalPort,
		TCPPath:      *path,
		UDPPath:      *udpPath,
		InternalAddr: "127.0.0.1",
		InternalPort: internalPort,
		TLS:          oldTLSEnabled,
		Host:         *host,
		Cert:         *cert,
		CertRaw:      *certRaw,
		Key:          *key,
	}, udpRelay)
	if err != nil {
		return nil, err
	}
	return &combinedWebSocketServer{tcp: instance, udp: udpRelay, router: router}, nil
}

func allocateLoopbackTCPPort() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", newError("failed to allocate internal tcp port").Base(err)
	}
	defer listener.Close()
	return strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), nil
}
