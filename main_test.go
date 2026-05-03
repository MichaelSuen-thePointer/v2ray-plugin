package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func withTCPOptionState(t *testing.T) {
	t.Helper()
	oldFastOpen := *fastOpen
	oldLocalAddr := *localAddr
	oldLocalPort := *localPort
	oldRemoteAddr := *remoteAddr
	oldRemotePort := *remotePort
	oldPath := *path
	oldHost := *host
	oldTLSEnabled := *tlsEnabled
	oldCert := *cert
	oldCertRaw := *certRaw
	oldKey := *key
	oldMode := *mode
	oldMux := *mux
	oldServer := *server
	oldFWMark := *fwmark

	*fastOpen = false
	*localAddr = "127.0.0.1"
	*localPort = "1984"
	*remoteAddr = "127.0.0.1"
	*remotePort = "1080"
	*path = "/"
	*host = "cloudfront.com"
	*tlsEnabled = false
	*cert = ""
	*certRaw = ""
	*key = ""
	*mode = "websocket"
	*mux = 1
	*server = false
	*fwmark = 0

	t.Cleanup(func() {
		*fastOpen = oldFastOpen
		*localAddr = oldLocalAddr
		*localPort = oldLocalPort
		*remoteAddr = oldRemoteAddr
		*remotePort = oldRemotePort
		*path = oldPath
		*host = oldHost
		*tlsEnabled = oldTLSEnabled
		*cert = oldCert
		*certRaw = oldCertRaw
		*key = oldKey
		*mode = oldMode
		*mux = oldMux
		*server = oldServer
		*fwmark = oldFWMark
	})
}

func withUDPOptionState(t *testing.T, mode string, timeout int) {
	t.Helper()
	oldMode := *udpMode
	oldTimeout := *udpTimeout
	*udpMode = mode
	*udpTimeout = timeout
	t.Cleanup(func() {
		*udpMode = oldMode
		*udpTimeout = oldTimeout
	})
}

func TestApplyUDPOptions(t *testing.T) {
	withUDPOptionState(t, "", 30)

	opts := Args{
		"udpMode":    []string{"quic"},
		"udpTimeout": []string{"45"},
	}

	if err := applyUDPOptions(opts); err != nil {
		t.Fatalf("applyUDPOptions returned error: %v", err)
	}
	if *udpMode != "quic" {
		t.Fatalf("udpMode = %q, want quic", *udpMode)
	}
	if *udpTimeout != 45 {
		t.Fatalf("udpTimeout = %d, want 45", *udpTimeout)
	}
}

func TestGenerateTCPStreamConfigKeepsDefaultWebSocket(t *testing.T) {
	withTCPOptionState(t)

	streamConfig, connectionReuse, err := generateTCPStreamConfig()
	if err != nil {
		t.Fatalf("generateTCPStreamConfig returned error: %v", err)
	}
	if streamConfig.ProtocolName != "websocket" {
		t.Fatalf("ProtocolName = %q, want websocket", streamConfig.ProtocolName)
	}
	if !connectionReuse {
		t.Fatal("connectionReuse = false, want true for default mux")
	}
	if *tlsEnabled {
		t.Fatal("tlsEnabled = true, want false for default websocket mode")
	}
}

func TestGenerateTCPStreamConfigIgnoresUDPMode(t *testing.T) {
	withTCPOptionState(t)
	withUDPOptionState(t, "quic", 30)

	streamConfig, _, err := generateTCPStreamConfig()
	if err != nil {
		t.Fatalf("generateTCPStreamConfig returned error: %v", err)
	}
	if streamConfig.ProtocolName != "websocket" {
		t.Fatalf("ProtocolName = %q, want websocket", streamConfig.ProtocolName)
	}
}

func TestGenerateTCPStreamConfigQUICEnablesTLS(t *testing.T) {
	withTCPOptionState(t)
	*mode = "quic"

	streamConfig, connectionReuse, err := generateTCPStreamConfig()
	if err != nil {
		t.Fatalf("generateTCPStreamConfig returned error: %v", err)
	}
	if streamConfig.ProtocolName != "quic" {
		t.Fatalf("ProtocolName = %q, want quic", streamConfig.ProtocolName)
	}
	if connectionReuse {
		t.Fatal("connectionReuse = true, want false for quic mode")
	}
	if !*tlsEnabled {
		t.Fatal("tlsEnabled = false, want true for quic mode")
	}
}

func TestValidateUDPOptionsAllowsDefaultDisabledMode(t *testing.T) {
	withUDPOptionState(t, "", 30)

	if err := validateUDPOptions(); err != nil {
		t.Fatalf("validateUDPOptions returned error: %v", err)
	}
}

func TestValidateUDPOptionsRejectsUnsupportedMode(t *testing.T) {
	withUDPOptionState(t, "websocket", 30)

	if err := validateUDPOptions(); err == nil {
		t.Fatal("validateUDPOptions returned nil, want unsupported mode error")
	}
}

func TestApplyUDPOptionsRejectsInvalidTimeout(t *testing.T) {
	withUDPOptionState(t, "", 30)

	opts := Args{"udpTimeout": []string{"soon"}}
	if err := applyUDPOptions(opts); err == nil {
		t.Fatal("applyUDPOptions returned nil, want invalid timeout error")
	}
}

func TestValidateUDPOptionsRejectsNonPositiveTimeout(t *testing.T) {
	withUDPOptionState(t, "quic", 0)

	if err := validateUDPOptions(); err == nil {
		t.Fatal("validateUDPOptions returned nil, want invalid timeout error")
	}
}

func TestNewUDPRelayFromOptionsDisabled(t *testing.T) {
	withTCPOptionState(t)
	withUDPOptionState(t, "", 30)

	relay, err := newUDPRelayFromOptions()
	if err != nil {
		t.Fatalf("newUDPRelayFromOptions returned error: %v", err)
	}
	if relay != nil {
		t.Fatal("newUDPRelayFromOptions returned relay, want nil")
	}
}

func TestNewUDPRelayFromOptionsEnabled(t *testing.T) {
	withTCPOptionState(t)
	withUDPOptionState(t, "quic", 45)
	*server = true
	*localAddr = "127.0.0.1|::1"
	*localPort = "1984"
	*remoteAddr = "127.0.0.1"
	*remotePort = "1080"
	*host = "example.com"

	relay, err := newUDPRelayFromOptions()
	if err != nil {
		t.Fatalf("newUDPRelayFromOptions returned error: %v", err)
	}
	if relay == nil {
		t.Fatal("newUDPRelayFromOptions returned nil, want relay")
	}
	if !relay.config.Server {
		t.Fatal("relay.config.Server = false, want true")
	}
	if relay.config.LocalAddr != "127.0.0.1|::1" {
		t.Fatalf("relay.config.LocalAddr = %q, want 127.0.0.1|::1", relay.config.LocalAddr)
	}
	if relay.config.Timeout != 45*time.Second {
		t.Fatalf("relay.config.Timeout = %s, want 45s", relay.config.Timeout)
	}
}

func TestUDPRelayCanShareTCPPortNumber(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen tcp returned error: %v", err)
	}
	defer tcpListener.Close()

	port := tcpListener.Addr().(*net.TCPAddr).Port
	relay := newUDPRelay(udpRelayConfig{
		LocalAddr: "127.0.0.1",
		LocalPort: strconv.Itoa(port),
		Timeout:   30 * time.Second,
	})
	if err := relay.Start(); err != nil {
		t.Fatalf("udp relay Start returned error: %v", err)
	}
	if err := relay.Close(); err != nil {
		t.Fatalf("udp relay Close returned error: %v", err)
	}
}

func TestUDPRelayPreservesDatagramBoundaries(t *testing.T) {
	clientRelay, serverRelay, clientAddr, closeRelays := startUDPRelayPair(t, 5*time.Second)
	defer closeRelays()
	_ = clientRelay
	_ = serverRelay

	appConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket app udp returned error: %v", err)
	}
	defer appConn.Close()

	first := []byte("first datagram")
	second := []byte("second datagram stays separate")
	writeUDPTestDatagram(t, appConn, clientAddr, first)
	writeUDPTestDatagram(t, appConn, clientAddr, second)

	gotFirst := readUDPTestDatagram(t, appConn)
	gotSecond := readUDPTestDatagram(t, appConn)
	if string(gotFirst) != string(first) {
		t.Fatalf("first response = %q, want %q", gotFirst, first)
	}
	if string(gotSecond) != string(second) {
		t.Fatalf("second response = %q, want %q", gotSecond, second)
	}
}

func TestUDPRelayRunsAlongsideTCPModes(t *testing.T) {
	for _, tcpMode := range []string{"websocket", "quic"} {
		t.Run(tcpMode, func(t *testing.T) {
			withTCPOptionState(t)
			withUDPOptionState(t, "quic", 30)
			*mode = tcpMode

			if _, _, err := generateTCPStreamConfig(); err != nil {
				t.Fatalf("generateTCPStreamConfig returned error: %v", err)
			}
			clientRelay, serverRelay, clientAddr, closeRelays := startUDPRelayPair(t, 5*time.Second)
			defer closeRelays()
			_ = clientRelay
			_ = serverRelay

			appConn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("net.ListenPacket app udp returned error: %v", err)
			}
			defer appConn.Close()

			payload := []byte("udp with tcp mode " + tcpMode)
			writeUDPTestDatagram(t, appConn, clientAddr, payload)
			if got := readUDPTestDatagram(t, appConn); string(got) != string(payload) {
				t.Fatalf("response = %q, want %q", got, payload)
			}
		})
	}
}

func TestUDPRelayExpiresIdleFlows(t *testing.T) {
	clientRelay, serverRelay, clientAddr, closeRelays := startUDPRelayPair(t, 200*time.Millisecond)
	defer closeRelays()

	appConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket app udp returned error: %v", err)
	}
	defer appConn.Close()

	writeUDPTestDatagram(t, appConn, clientAddr, []byte("flow trigger"))
	_ = readUDPTestDatagram(t, appConn)

	eventually(t, time.Second, func() bool {
		clientRelay.mu.Lock()
		defer clientRelay.mu.Unlock()
		return len(clientRelay.clientFlows) == 1
	})
	eventually(t, time.Second, func() bool {
		serverRelay.mu.Lock()
		defer serverRelay.mu.Unlock()
		return len(serverRelay.serverFlows) == 1
	})
	eventually(t, 2*time.Second, func() bool {
		clientRelay.mu.Lock()
		defer clientRelay.mu.Unlock()
		return len(clientRelay.clientFlows) == 0
	})
	eventually(t, 2*time.Second, func() bool {
		serverRelay.mu.Lock()
		defer serverRelay.mu.Unlock()
		return len(serverRelay.serverFlows) == 0
	})
}

func startUDPRelayPair(t *testing.T, timeout time.Duration) (*udpRelay, *udpRelay, net.Addr, func()) {
	t.Helper()

	echoConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket echo udp returned error: %v", err)
	}
	echoDone := make(chan struct{})
	go serveUDPEcho(echoConn, echoDone)

	certPath, keyPath := writeTestCertificate(t, "127.0.0.1")
	echoPort := strconv.Itoa(echoConn.LocalAddr().(*net.UDPAddr).Port)
	serverRelay := newUDPRelay(udpRelayConfig{
		Server:     true,
		LocalAddr:  "127.0.0.1",
		LocalPort:  "0",
		RemoteAddr: "127.0.0.1",
		RemotePort: echoPort,
		Host:       "127.0.0.1",
		Cert:       certPath,
		Key:        keyPath,
		Timeout:    timeout,
	})
	if err := serverRelay.Start(); err != nil {
		echoConn.Close()
		<-echoDone
		t.Fatalf("server udp relay Start returned error: %v", err)
	}
	serverPort := strconv.Itoa(serverRelay.listeners[0].LocalAddr().(*net.UDPAddr).Port)

	clientRelay := newUDPRelay(udpRelayConfig{
		LocalAddr:  "127.0.0.1",
		LocalPort:  "0",
		RemoteAddr: "127.0.0.1",
		RemotePort: serverPort,
		Host:       "127.0.0.1",
		Cert:       certPath,
		Timeout:    timeout,
	})
	if err := clientRelay.Start(); err != nil {
		serverRelay.Close()
		echoConn.Close()
		<-echoDone
		t.Fatalf("client udp relay Start returned error: %v", err)
	}
	clientAddr := clientRelay.listeners[0].LocalAddr()

	closeRelays := func() {
		if err := clientRelay.Close(); err != nil {
			t.Fatalf("client udp relay Close returned error: %v", err)
		}
		if err := serverRelay.Close(); err != nil {
			t.Fatalf("server udp relay Close returned error: %v", err)
		}
		echoConn.Close()
		<-echoDone
	}
	return clientRelay, serverRelay, clientAddr, closeRelays
}

func serveUDPEcho(conn net.PacketConn, done chan<- struct{}) {
	defer close(done)
	buf := make([]byte, udpRelayMaxPacketSize)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		_, _ = conn.WriteTo(payload, addr)
	}
}

func writeUDPTestDatagram(t *testing.T, conn net.PacketConn, addr net.Addr, payload []byte) {
	t.Helper()
	if _, err := conn.WriteTo(payload, addr); err != nil {
		t.Fatalf("udp WriteTo returned error: %v", err)
	}
}

func readUDPTestDatagram(t *testing.T, conn net.PacketConn) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline returned error: %v", err)
	}
	buf := make([]byte, udpRelayMaxPacketSize)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("udp ReadFrom returned error: %v", err)
	}
	payload := make([]byte, n)
	copy(payload, buf[:n])
	return payload
}

func eventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !condition() {
		t.Fatal("condition was not met before timeout")
	}
}

func writeTestCertificate(t *testing.T, host string) (string, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey returned error: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP(host)},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate returned error: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("os.WriteFile cert returned error: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("os.WriteFile key returned error: %v", err)
	}
	return certPath, keyPath
}

type fakeCoreServer struct {
	started bool
	closed  bool
}

func (s *fakeCoreServer) Start() error {
	s.started = true
	return nil
}

func (s *fakeCoreServer) Close() error {
	s.closed = true
	return nil
}

func TestPluginServerClosesTCPWhenUDPStartFails(t *testing.T) {
	tcp := &fakeCoreServer{}
	server := &pluginServer{
		tcp: tcp,
		udp: newUDPRelay(udpRelayConfig{
			LocalAddr: "127.0.0.1",
			LocalPort: "not-a-port",
			Timeout:   30 * time.Second,
		}),
	}

	if err := server.Start(); err == nil {
		t.Fatal("pluginServer Start returned nil, want udp start error")
	}
	if !tcp.started {
		t.Fatal("tcp server was not started")
	}
	if !tcp.closed {
		t.Fatal("tcp server was not closed after udp start failure")
	}
}

func TestPluginServerReturnsTCPStartError(t *testing.T) {
	startErr := errors.New("start failed")
	server := &pluginServer{
		tcp: &failingCoreServer{startErr: startErr},
	}

	if err := server.Start(); !errors.Is(err, startErr) {
		t.Fatalf("pluginServer Start error = %v, want %v", err, startErr)
	}
}

type failingCoreServer struct {
	startErr error
}

func (s *failingCoreServer) Start() error {
	return s.startErr
}

func (s *failingCoreServer) Close() error {
	return nil
}
