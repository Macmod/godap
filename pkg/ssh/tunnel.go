package sshtunnel

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Config holds all parameters needed to establish an SSH tunnel.
type Config struct {
	Host                  string
	Port                  int // 0 means use 22
	User                  string
	AuthMethod            string // "password", "key", or "agent"
	Password              string
	KeyFile               string
	KeyPassphrase         string
	InsecureIgnoreHostKey bool
	// HostKeyCallback overrides the default known_hosts check when non-nil.
	// Primarily used for testing (pass ssh.InsecureIgnoreHostKey()).
	HostKeyCallback ssh.HostKeyCallback
}

// HostKeyUnknownError is returned when the SSH server's host key is not
// present in known_hosts and InsecureIgnoreHostKey is false.
type HostKeyUnknownError struct {
	Host string
}

func (e *HostKeyUnknownError) Error() string {
	return fmt.Sprintf(
		"unknown SSH host key for %q — run: ssh-keyscan %s >> ~/.ssh/known_hosts or use --ssh-ignore-host-key",
		e.Host, e.Host,
	)
}

// Tunnel forwards TCP connections from a local listener through an SSH client
// to a remote endpoint.
type Tunnel struct {
	config     Config
	client     *ssh.Client
	listener   net.Listener
	wg         sync.WaitGroup
	done       chan struct{}
	remoteHost string
	remotePort int
}

// New establishes an SSH connection and begins listening on a random local port.
// Connections to the local port are forwarded through the SSH client to
// remoteHost:remotePort.
func New(cfg Config, remoteHost string, remotePort int) (*Tunnel, error) {
	port := cfg.Port
	if port == 0 {
		port = 22
	}

	hostKeyCallback, err := buildHostKeyCallback(cfg)
	if err != nil {
		return nil, err
	}

	authMethods, err := buildAuthMethods(cfg)
	if err != nil {
		return nil, err
	}

	clientCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, port)
	client, err := ssh.Dial("tcp", addr, clientCfg)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		client.Close()
		return nil, err
	}

	t := &Tunnel{
		config:     cfg,
		client:     client,
		listener:   listener,
		done:       make(chan struct{}),
		remoteHost: remoteHost,
		remotePort: remotePort,
	}

	go t.accept()
	return t, nil
}

// LocalAddr returns the local address the tunnel is listening on (e.g. "127.0.0.1:54321").
func (t *Tunnel) LocalAddr() string {
	return t.listener.Addr().String()
}

// LocalPort returns the local port the tunnel is listening on.
func (t *Tunnel) LocalPort() int {
	return t.listener.Addr().(*net.TCPAddr).Port
}

// Close shuts down the tunnel, waiting for all in-flight forwarded connections
// to finish. Safe to call multiple times.
func (t *Tunnel) Close() error {
	select {
	case <-t.done:
		return nil // already closed
	default:
		close(t.done)
	}
	t.listener.Close()
	t.client.Close()
	t.wg.Wait()
	return nil
}

func (t *Tunnel) accept() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			select {
			case <-t.done:
				return // expected shutdown
			default:
				return // unexpected error
			}
		}
		t.wg.Add(1)
		go t.forward(conn)
	}
}

func (t *Tunnel) forward(localConn net.Conn) {
	defer t.wg.Done()
	defer localConn.Close()

	remoteAddr := fmt.Sprintf("%s:%d", t.remoteHost, t.remotePort)
	remoteConn, err := t.client.Dial("tcp", remoteAddr)
	if err != nil {
		return
	}
	defer remoteConn.Close()

	// Bidirectional copy: wait for one direction to finish.
	// Deferred Close() calls on both conns unblock the other goroutine.
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(remoteConn, localConn) //nolint:errcheck
		done <- struct{}{}
	}()
	go func() {
		io.Copy(localConn, remoteConn) //nolint:errcheck
		done <- struct{}{}
	}()
	<-done
}

func buildHostKeyCallback(cfg Config) (ssh.HostKeyCallback, error) {
	if cfg.InsecureIgnoreHostKey {
		return ssh.InsecureIgnoreHostKey(), nil //nolint:gosec
	}

	if cfg.HostKeyCallback != nil {
		return cfg.HostKeyCallback, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return ssh.InsecureIgnoreHostKey(), nil //nolint:gosec
	}

	knownHostsFile := filepath.Join(home, ".ssh", "known_hosts")
	if _, err := os.Stat(knownHostsFile); os.IsNotExist(err) {
		return ssh.InsecureIgnoreHostKey(), nil //nolint:gosec
	}

	khCallback, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load known_hosts: %w", err)
	}

	// Wrap the knownhosts callback to translate unknown-host errors into
	// HostKeyUnknownError so callers can show a helpful message.
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := khCallback(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) && len(keyErr.Want) == 0 {
			// Unknown host (not a mismatch — mismatch propagates raw)
			return &HostKeyUnknownError{Host: cfg.Host}
		}
		return err
	}, nil
}

func buildAuthMethods(cfg Config) ([]ssh.AuthMethod, error) {
	switch cfg.AuthMethod {
	case "key":
		keyData, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read SSH key file %q: %w", cfg.KeyFile, err)
		}
		var signer ssh.Signer
		if cfg.KeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(cfg.KeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyData)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse SSH key: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil

	case "agent":
		sockPath := os.Getenv("SSH_AUTH_SOCK")
		if sockPath == "" {
			return nil, fmt.Errorf("SSH_AUTH_SOCK not set; cannot use agent auth")
		}
		conn, err := net.Dial("unix", sockPath)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to SSH agent: %w", err)
		}
		agentClient := agent.NewClient(conn)
		return []ssh.AuthMethod{ssh.PublicKeysCallback(agentClient.Signers)}, nil

	default: // "password"
		return []ssh.AuthMethod{ssh.Password(cfg.Password)}, nil
	}
}
