package sshtunnel_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	sshtunnel "github.com/Macmod/godap/v2/pkg/ssh"
)

// generateTestSigner creates an RSA host/user key for use in tests.
func generateTestSigner(t *testing.T) gossh.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// startTestSSHServer starts a minimal in-process SSH server that accepts
// password auth for user/password and forwards direct-tcpip channels.
// Returns the server address and a cleanup function.
func startTestSSHServer(t *testing.T, user, password string) (addr string, cleanup func()) {
	t.Helper()

	hostKey := generateTestSigner(t)

	serverConfig := &gossh.ServerConfig{
		PasswordCallback: func(conn gossh.ConnMetadata, pw []byte) (*gossh.Permissions, error) {
			if conn.User() == user && string(pw) == password {
				return &gossh.Permissions{}, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}
	serverConfig.AddHostKey(hostKey)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestSSHConn(conn, serverConfig)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

// startTestSSHServerWithKeyAuth starts an SSH server that only accepts
// public key authentication for the given user.
func startTestSSHServerWithKeyAuth(t *testing.T, user string, authorizedKey gossh.PublicKey) (addr string, cleanup func()) {
	t.Helper()

	hostKey := generateTestSigner(t)
	authKeyBytes := authorizedKey.Marshal()

	serverConfig := &gossh.ServerConfig{
		PublicKeyCallback: func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if conn.User() == user && string(key.Marshal()) == string(authKeyBytes) {
				return &gossh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unauthorized key")
		},
	}
	serverConfig.AddHostKey(hostKey)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestSSHConn(conn, serverConfig)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

// directTCPIPPayload is the wire format of a direct-tcpip channel request.
type directTCPIPPayload struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

func handleTestSSHConn(conn net.Conn, cfg *gossh.ServerConfig) {
	sshConn, chans, reqs, err := gossh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go gossh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" {
			newChan.Reject(gossh.UnknownChannelType, "only direct-tcpip supported")
			continue
		}

		// Parse the forwarding target from the channel extra data.
		data := newChan.ExtraData()
		// Manual parse: string(destAddr), uint32(destPort), string(origAddr), uint32(origPort)
		destAddr, rest, ok := parseSSHString(data)
		if !ok {
			newChan.Reject(gossh.Prohibited, "bad payload")
			continue
		}
		if len(rest) < 4 {
			newChan.Reject(gossh.Prohibited, "bad payload")
			continue
		}
		destPort := binary.BigEndian.Uint32(rest[:4])

		ch, _, err := newChan.Accept()
		if err != nil {
			continue
		}

		go func(ch gossh.Channel, dest string, port uint32) {
			defer ch.Close()
			target, err := net.Dial("tcp", net.JoinHostPort(dest, strconv.FormatUint(uint64(port), 10)))
			if err != nil {
				return
			}
			defer target.Close()
			done := make(chan struct{}, 2)
			go func() { io.Copy(target, ch); done <- struct{}{} }() //nolint:errcheck
			go func() { io.Copy(ch, target); done <- struct{}{} }() //nolint:errcheck
			<-done
		}(ch, destAddr, destPort)
	}
}

// parseSSHString parses a length-prefixed SSH string from b.
func parseSSHString(b []byte) (s string, rest []byte, ok bool) {
	if len(b) < 4 {
		return "", nil, false
	}
	n := int(binary.BigEndian.Uint32(b[:4]))
	if len(b) < 4+n {
		return "", nil, false
	}
	return string(b[4 : 4+n]), b[4+n:], true
}

// splitHostPort splits an address and returns host and port as int.
func splitHostPort(t *testing.T, addr string) (host string, port int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return h, n
}

// TestPasswordAuth verifies that the tunnel can be established with password auth.
func TestPasswordAuth(t *testing.T) {
	sshAddr, cleanup := startTestSSHServer(t, "testuser", "testpass")
	defer cleanup()

	host, port := splitHostPort(t, sshAddr)

	// We don't need a real LDAP target — just use any listening port.
	// The tunnel should be created successfully even if no connections flow.
	dummyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dummyLn.Close()
	dummyPort := dummyLn.Addr().(*net.TCPAddr).Port

	tun, err := sshtunnel.New(sshtunnel.Config{
		Host:            host,
		Port:            port,
		User:            "testuser",
		AuthMethod:      "password",
		Password:        "testpass",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec
	}, "127.0.0.1", dummyPort)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer tun.Close()

	if tun.LocalPort() == 0 {
		t.Error("expected non-zero local port")
	}
}

// TestKeyAuth verifies that the tunnel can be established with key-based auth.
func TestKeyAuth(t *testing.T) {
	userSigner := generateTestSigner(t)
	sshAddr, cleanup := startTestSSHServerWithKeyAuth(t, "keyuser", userSigner.PublicKey())
	defer cleanup()

	host, port := splitHostPort(t, sshAddr)

	// Write the private key to a temp file.
	privKeyPEM := gossh.MarshalAuthorizedKey(userSigner.PublicKey())
	// We need the private key in PEM format; regenerate from scratch using crypto/rsa.
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, err := gossh.NewSignerFromKey(rsaPriv)
	if err != nil {
		t.Fatal(err)
	}
	_ = privKeyPEM // discard the public key bytes above

	// Register the RSA signer's public key with the server.
	sshAddr2, cleanup2 := startTestSSHServerWithKeyAuth(t, "keyuser2", rsaSigner.PublicKey())
	defer cleanup2()

	host2, port2 := splitHostPort(t, sshAddr2)

	// Marshal private key to PEM using x/crypto.
	privBytes := gossh.MarshalAuthorizedKey(rsaSigner.PublicKey()) // public, not private
	_ = privBytes
	// Use the HostKeyCallback injection path instead of a key file to avoid
	// writing PEM encoding logic in the test.
	dummyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dummyLn.Close()
	dummyPort := dummyLn.Addr().(*net.TCPAddr).Port

	// Dial directly using the signer to verify the auth path works end-to-end.
	// We pass an InMemoryKey via a custom dialer approach via HostKeyCallback.
	// Since we can't inject the auth method directly, verify via normal Dial.
	clientCfg := &gossh.ClientConfig{
		User:            "keyuser2",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(rsaSigner)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec
	}
	client, err := gossh.Dial("tcp", fmt.Sprintf("%s:%d", host2, port2), clientCfg)
	if err != nil {
		t.Fatalf("direct key auth dial failed: %v", err)
	}
	client.Close()

	// Also verify the tunnel package handles key files correctly via a temp file.
	t.Run("key file", func(t *testing.T) {
		keyFile := writePrivateKeyFile(t, rsaPriv)
		sshAddr3, cleanup3 := startTestSSHServerWithKeyAuth(t, "keyuser3", rsaSigner.PublicKey())
		defer cleanup3()
		host3, port3 := splitHostPort(t, sshAddr3)

		tun, err := sshtunnel.New(sshtunnel.Config{
			Host:            host3,
			Port:            port3,
			User:            "keyuser3",
			AuthMethod:      "key",
			KeyFile:         keyFile,
			HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec
		}, "127.0.0.1", dummyPort)
		if err != nil {
			t.Fatalf("New() with key file failed: %v", err)
		}
		tun.Close()
	})

	// Silence unused variable warning for host/port from first test
	_ = host
	_ = port
}

// writePrivateKeyFile writes an RSA private key to a temp file in OpenSSH PEM format.
func writePrivateKeyFile(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	pemBlock, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	path := t.TempDir() + "/id_rsa"
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestTunnelForwarding verifies that data flows correctly through the tunnel.
func TestTunnelForwarding(t *testing.T) {
	sshAddr, cleanup := startTestSSHServer(t, "u", "p")
	defer cleanup()

	// Start an in-process echo server.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c) //nolint:errcheck
		}
	}()

	host, sshPort := splitHostPort(t, sshAddr)
	echoPort := echoLn.Addr().(*net.TCPAddr).Port

	tun, err := sshtunnel.New(sshtunnel.Config{
		Host:            host,
		Port:            sshPort,
		User:            "u",
		AuthMethod:      "password",
		Password:        "p",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec
	}, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer tun.Close()

	conn, err := net.Dial("tcp", tun.LocalAddr())
	if err != nil {
		t.Fatalf("Dial local tunnel addr failed: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("echo got %q, want %q", buf, msg)
	}
}

// TestCloseStopsAccepting verifies that after Close(), the local address
// is no longer accepting new connections.
func TestCloseStopsAccepting(t *testing.T) {
	sshAddr, cleanup := startTestSSHServer(t, "u", "p")
	defer cleanup()

	dummyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dummyLn.Close()

	host, port := splitHostPort(t, sshAddr)

	tun, err := sshtunnel.New(sshtunnel.Config{
		Host:            host,
		Port:            port,
		User:            "u",
		AuthMethod:      "password",
		Password:        "p",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec
	}, "127.0.0.1", dummyLn.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}

	localAddr := tun.LocalAddr()
	tun.Close()

	conn, err := net.Dial("tcp", localAddr)
	if err == nil {
		conn.Close()
		t.Error("expected Dial to fail after Close(), but it succeeded")
	}
}

// TestBadSSHHost verifies that New() returns an error when the SSH server
// address is unreachable.
func TestBadSSHHost(t *testing.T) {
	_, err := sshtunnel.New(sshtunnel.Config{
		Host:            "127.0.0.1",
		Port:            1, // no server listening here
		User:            "u",
		AuthMethod:      "password",
		Password:        "p",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec
	}, "127.0.0.1", 22)
	if err == nil {
		t.Error("expected error for unreachable SSH host, got nil")
	}
}
