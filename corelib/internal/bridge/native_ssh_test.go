package bridge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/internal/privatefile"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/net/proxy"
)

const nativeSSHCommand = "justconnect-fixture-probe"
const nativeSSHReply = "JustConnect authenticated SSH command\n"

type sshPrefixConn struct {
	net.Conn
	reader io.Reader
}

func (c sshPrefixConn) Read(data []byte) (int, error) { return c.reader.Read(data) }

func enableNativeSSH(t *testing.T, g *gateway) string {
	t.Helper()
	_, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ssh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	_, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ssh.NewSignerFromKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	configuration := &ssh.ServerConfig{PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if metadata.User() != "fixture" || !bytes.Equal(key.Marshal(), client.PublicKey().Marshal()) {
			return nil, fmt.Errorf("unknown fixture SSH identity")
		}
		return nil, nil
	}}
	configuration.AddHostKey(server)
	g.sshHandler.Store(func(connection net.Conn, prefix []byte) {
		_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
		buffered := sshPrefixConn{connection, io.MultiReader(bytes.NewReader(prefix), connection)}
		connectionSSH, channels, requests, err := ssh.NewServerConn(buffered, configuration)
		if err != nil {
			return
		}
		done := make(chan struct{})
		go func() { ssh.DiscardRequests(requests); close(done) }()
		defer func() { connectionSSH.Close(); <-done }()
		for incoming := range channels {
			if incoming.ChannelType() != "session" {
				_ = incoming.Reject(ssh.UnknownChannelType, "fixture accepts only a command session")
				continue
			}
			channel, requests, err := incoming.Accept()
			if err != nil {
				return
			}
			defer channel.Close()
			for request := range requests {
				var command struct{ Command string }
				accepted := request.Type == "exec" && ssh.Unmarshal(request.Payload, &command) == nil && command.Command == nativeSSHCommand
				_ = request.Reply(accepted, nil)
				if !accepted {
					continue
				}
				g.sshCount.Add(1)
				_, _ = io.WriteString(channel, nativeSSHReply)
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				_ = channel.Close()
				_ = connectionSSH.Wait()
				return
			}
		}
	})
	directory := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(directory, name)
		file, err := privatefile.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.Write(data)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatalf("private SSH fixture file: %v, %v", writeErr, closeErr)
		}
		return path
	}
	private, err := ssh.MarshalPrivateKey(clientKey, "owned disposable SSH fixture")
	if err != nil {
		t.Fatal(err)
	}
	key := write("identity", pem.EncodeToMemory(private))
	known := write("known_hosts", append([]byte("justconnect-native-fixture "), ssh.MarshalAuthorizedKey(server.PublicKey())...))
	quote := func(path string) string { return `"` + filepath.ToSlash(path) + `"` }
	config := "Host *\n User fixture\n Port 80\n BatchMode yes\n IdentitiesOnly yes\n IdentityAgent none\n StrictHostKeyChecking yes\n GlobalKnownHostsFile none\n HostKeyAlias justconnect-native-fixture\n ConnectTimeout 5\n ConnectionAttempts 1\n IdentityFile " + quote(key) + "\n UserKnownHostsFile " + quote(known) + "\n"
	path := write("config", []byte(config))
	probe, err := json.Marshal(map[string]string{"config": path, "command": nativeSSHCommand, "expected": nativeSSHReply, "hostname": "campus.test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("JC_NATIVE_SSH_PROBE", string(probe))
	return path
}

func TestNativeSSHFixtureWithOpenSSH(t *testing.T) {
	program, err := exec.LookPath("ssh")
	if err != nil {
		t.Fatal("OpenSSH client is required for the terminal contract:", err)
	}
	g := newGateway(t)
	config := enableNativeSSH(t, g)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		for attempt := 0; attempt < 2; attempt++ {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			g.sshHandler.Load().(func(net.Conn, []byte))(connection, nil)
			connection.Close()
		}
	}()
	command := exec.CommandContext(t.Context(), program, "-F", config, "-p", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), "127.0.0.1", nativeSSHCommand)
	output, err := command.CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != strings.TrimSpace(nativeSSHReply) || g.sshCount.Load() != 1 {
		t.Fatalf("actual OpenSSH command: %v count=%d\n%s", err, g.sshCount.Load(), output)
	}
	wrongConfig := enableNativeSSH(t, newGateway(t))
	command = exec.CommandContext(t.Context(), program, "-F", wrongConfig, "-p", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), "127.0.0.1", nativeSSHCommand)
	output, err = command.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("Host key verification failed")) || g.sshCount.Load() != 1 {
		t.Fatalf("OpenSSH accepted a different pinned server identity: %v count=%d\n%s", err, g.sshCount.Load(), output)
	}
	<-done

	engine := New(RunProtocol)
	handle := create(t, engine)
	configuration := g.config(t)
	configuration.Listeners.SOCKS = freeAddress(t)
	startProtocol(t, engine, handle, configuration)
	if ready := next(t, engine, handle); ready.State != "ready" {
		t.Fatal(ready)
	}
	transport, err := proxy.SOCKS5("tcp", configuration.Listeners.SOCKS, nil, &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := transport.(proxy.ContextDialer).DialContext(t.Context(), "tcp", "campus.test:80")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	key, err := os.ReadFile(filepath.Join(filepath.Dir(config), "identity"))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	verify, err := knownhosts.New(filepath.Join(filepath.Dir(config), "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	client, channels, requests, err := ssh.NewClientConn(connection, "justconnect-native-fixture:22", &ssh.ClientConfig{
		User: "fixture", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: verify,
	})
	if err != nil {
		t.Fatal("SSH through actual authenticated core and campus tunnel:", err)
	}
	sshClient := ssh.NewClient(client, channels, requests)
	defer sshClient.Close()
	session, err := sshClient.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	output, err = session.CombinedOutput(nativeSSHCommand)
	_ = session.Close()
	_ = sshClient.Close()
	if err != nil || string(output) != nativeSSHReply || g.sshCount.Load() != 2 || g.tcpCount.Load() != 1 {
		t.Fatalf("campus SSH command: %v commands=%d TCP=%d\n%s", err, g.sshCount.Load(), g.tcpCount.Load(), output)
	}
	if engine.Stop(handle, 3000) != OK || next(t, engine, handle).Type != "terminal" {
		t.Fatal("SSH campus session did not stop")
	}
}
