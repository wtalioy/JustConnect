package atrust

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client"
	"github.com/wtalioy/JustConnect/corelib/client/atrust/auth"
	"github.com/wtalioy/JustConnect/corelib/client/authchallenge"
	"github.com/wtalioy/JustConnect/corelib/internal/ipresource"
)

type SessionOptions struct {
	Username string
	SID      string
	DeviceID string
	SignKey  string
}

type ClientOptions struct {
	Session         SessionOptions
	UnderlayDialer  client.UnderlayDialer
	TLSKeyLogWriter io.Writer
	Language        string
	Diagnostic      func(string)
}

type SetupOptions struct {
	ServerAddress            string
	ServerPort               int
	LoginMethod              auth.LoginMethod
	TOTPSecret               string
	ClientData               []byte
	ResourceData             []byte
	BestNodesRefreshInterval time.Duration
	ChallengeHandler         authchallenge.Handler
	SessionRefreshInterval   time.Duration
	SaveClientData           func([]byte) error
}

type Client struct {
	Username     string
	SID          string
	DeviceID     string
	ConnectionID string
	SignKey      string

	setupMu      sync.Mutex
	setupStarted bool
	authSession  *auth.Session
	workers      sync.WaitGroup
	failures     chan error
	failureOnce  sync.Once
	language     string
	diagnostic   func(string)
	sessionMu    sync.RWMutex
	sessionErr   error
	refreshDone  chan struct{}

	serverAddress   string
	ipResources     []client.IPResource
	resourceIndex   *ipresource.Index
	domainResources client.DomainResources

	dnsResource map[string][]net.IP
	dnsServer   string
	dnsServers  []string

	MajorNodeGroup   string
	NodeGroups       map[string]NodeGroup
	BestNodes        map[string]string
	BestNodesRWMutex sync.RWMutex

	ipMu sync.RWMutex
	ip   net.IP // Client IP

	ipUpdateMu      sync.RWMutex
	ipUpdateHandler func(net.IP) error

	l3Tunnel   *L3Tunnel
	l3TunnelMu sync.Mutex
	tcpMu      sync.Mutex
	tcpConns   map[*tcpTunnelConn]struct{}

	lifecycleCtx     context.Context
	lifecycleCancel  context.CancelFunc
	closeOnce        sync.Once
	underlayDialer   client.UnderlayDialer
	tlsKeyLogWriter  io.Writer
	tcpTunnelZeroRTT bool
}

func NewClient(options ClientOptions) *Client {
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	return &Client{
		Username:        options.Session.Username,
		SID:             options.Session.SID,
		DeviceID:        options.Session.DeviceID,
		SignKey:         options.Session.SignKey,
		underlayDialer:  options.UnderlayDialer,
		tlsKeyLogWriter: options.TLSKeyLogWriter,
		language:        options.Language,
		diagnostic:      options.Diagnostic,
		failures:        make(chan error, 1),
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
	}
}

func (c *Client) canResume(resourceData []byte) bool {
	return c.SID != "" && c.DeviceID != "" && resourceData != nil
}

func (c *Client) Close() {
	c.closeOnce.Do(func() {
		c.lifecycleCancel()
		c.setupMu.Lock()
		defer c.setupMu.Unlock()
		c.workers.Wait()
		c.tcpMu.Lock()
		connections := make([]*tcpTunnelConn, 0, len(c.tcpConns))
		for conn := range c.tcpConns {
			connections = append(connections, conn)
		}
		c.tcpMu.Unlock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		if c.authSession != nil {
			c.authSession.Close()
		}
		c.l3TunnelMu.Lock()
		tunnel := c.l3Tunnel
		c.l3TunnelMu.Unlock()
		if tunnel != nil {
			tunnel.Close()
		}
	})
}

func (c *Client) IP() (net.IP, error) {
	c.ipMu.RLock()
	defer c.ipMu.RUnlock()
	if c.ip == nil {
		return nil, errors.New("IP not available")
	}

	return append(net.IP(nil), c.ip.To4()...), nil
}

func (c *Client) setIP(ip net.IP) {
	c.ipMu.Lock()
	c.ip = append(net.IP(nil), ip...)
	c.ipMu.Unlock()
}

func (c *Client) SetIPUpdateHandler(handler func(net.IP) error) {
	c.ipUpdateMu.Lock()
	c.ipUpdateHandler = handler
	c.ipUpdateMu.Unlock()
}

func (c *Client) applyIPUpdate(ip net.IP) error {
	c.ipUpdateMu.RLock()
	handler := c.ipUpdateHandler
	c.ipUpdateMu.RUnlock()
	if handler == nil {
		return errors.New("network stack does not support virtual IP updates")
	}
	return handler(append(net.IP(nil), ip...))
}

func (c *Client) IPResources() ([]client.IPResource, error) {
	if c.ipResources == nil {
		return nil, errors.New("IP resources not available")
	}

	return c.ipResources, nil
}

func (c *Client) DomainResources() (client.DomainResources, error) {
	if c.domainResources == nil {
		return nil, errors.New("domain resources not available")
	}

	return c.domainResources, nil
}

func (c *Client) DNSResource() (map[string][]net.IP, error) {
	if c.dnsResource == nil {
		return nil, errors.New("DNS resource not available")
	}

	return c.dnsResource, nil
}

func (c *Client) DNSServer() (string, error) {
	if c.dnsServer == "" {
		return "", errors.New("DNS server not available")
	}

	return c.dnsServer, nil
}

func (c *Client) DNSServers() ([]string, error) {
	if len(c.dnsServers) == 0 {
		return nil, errors.New("DNS servers not available")
	}
	return append([]string(nil), c.dnsServers...), nil
}

func randHex(n int) string {
	numBytes := (n + 1) / 2
	b := make([]byte, numBytes)
	_, _ = rand.Read(b)
	return strings.ToUpper(hex.EncodeToString(b)[:n])
}

func (c *Client) GetAuthInfoList(ctx context.Context, serverAddress string, serverPort int) ([]auth.AuthInfo, error) {
	if c.underlayDialer == nil {
		return nil, errors.New("underlay dialer is required")
	}
	queryCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.lifecycleCtx, cancel)
	defer func() { stop(); cancel() }()
	if c.lifecycleCtx.Err() != nil {
		cancel()
	}
	sess := auth.NewSessionContext(queryCtx, net.JoinHostPort(serverAddress, fmt.Sprint(serverPort)), c.tlsKeyLogWriter, c.underlayDialer.DialContext)
	defer sess.Close()
	sess.Language = c.language
	sess.Diagnostic = c.diagnostic
	return sess.GetAuthInfoList()
}

func (c *Client) CanUseTCPTunnel() bool {
	return true
}

func (c *Client) NewL3Conn() (io.ReadWriteCloser, error) {
	c.l3TunnelMu.Lock()
	tunnel := c.l3Tunnel
	c.l3TunnelMu.Unlock()
	if tunnel == nil {
		return nil, errors.New("L3 tunnel not initialized")
	}
	return tunnel.NewL3Conn()
}

func (c *Client) SetupContext(ctx context.Context, options SetupOptions) ([]byte, error) {
	c.setupMu.Lock()
	defer c.setupMu.Unlock()
	if c.lifecycleCtx.Err() != nil {
		return nil, context.Canceled
	}
	if c.setupStarted {
		return nil, errors.New("client setup already attempted")
	}
	c.setupStarted = true
	setupCtx, cancelSetup := context.WithCancel(ctx)
	defer cancelSetup()
	stopLifecycleCancellation := context.AfterFunc(c.lifecycleCtx, cancelSetup)
	defer stopLifecycleCancellation()
	if err := setupCtx.Err(); err != nil {
		return nil, err
	}
	if c.underlayDialer == nil {
		return nil, errors.New("underlay dialer is required")
	}
	c.serverAddress = options.ServerAddress

	var clientAuthData auth.ClientAuthData
	if options.ClientData != nil {
		if err := json.Unmarshal(options.ClientData, &clientAuthData); err != nil {

			return nil, err
		}
	}

	if clientAuthData.DeviceID == "" && c.DeviceID != "" {
		clientAuthData.DeviceID = c.DeviceID
	}

	authServerHost := net.JoinHostPort(options.ServerAddress, fmt.Sprint(options.ServerPort))
	sess := auth.NewSessionContext(setupCtx, authServerHost, c.tlsKeyLogWriter, c.underlayDialer.DialContext)
	c.authSession = sess
	sess.Diagnostic = c.diagnostic
	sess.Language = c.language
	success := false
	defer func() {
		if !success {
			sess.Close()
			if c.l3Tunnel != nil {
				c.l3Tunnel.Close()
			}
		}
	}()
	serverVersionInfo, manifestErr := sess.ServerVersionInfo()
	if err := setupCtx.Err(); err != nil {
		return nil, err
	}
	serverVersionInfo, err := resolveServerVersionInfo(clientAuthData.ServerVersionInfo, serverVersionInfo, manifestErr)
	if err != nil {
		return nil, err
	}
	if manifestErr != nil && c.diagnostic != nil {
		c.diagnostic("manifest_cached")
	}
	clientAuthData.ServerVersionInfo = serverVersionInfo
	parsedServerVersion, err := auth.ParseServerVersionInfo(serverVersionInfo)
	if err != nil {
		return nil, err
	}
	c.tcpTunnelZeroRTT = parsedServerVersion.TCPTunnelZeroRTT()

	resourceData := options.ResourceData
	if c.canResume(resourceData) {

		c.ConnectionID = buildConnectionID(c.DeviceID)
		if c.SignKey == "" {
			c.SignKey = randHex(64)
		}
		sess.Restore(c.DeviceID, c.SID, clientAuthData.Cookies)
	} else {
		if clientAuthData.DeviceID == "" {
			clientAuthData.DeviceID = strings.ToLower(randHex(32))
		}
		c.DeviceID = clientAuthData.DeviceID
		c.ConnectionID = buildConnectionID(c.DeviceID)
		c.SignKey = randHex(64)

		loginResult, err := sess.Login(options.LoginMethod, auth.LoginOptions{
			DeviceID:         c.DeviceID,
			Cookies:          clientAuthData.Cookies,
			TOTPSecret:       options.TOTPSecret,
			ChallengeHandler: options.ChallengeHandler,
		})
		if err != nil {

			return nil, err
		}
		c.Username = loginResult.Username

		resourceData, err = sess.ClientResource()
		if err != nil {

			return nil, err
		}

	}
	snapshot, err := sess.Snapshot()
	if err != nil {
		return nil, err
	}
	c.setSessionSID(snapshot.SID, nil)
	clientAuthData.DeviceID = c.DeviceID
	clientAuthData.Cookies = snapshot.Cookies
	authData, err := json.Marshal(clientAuthData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal client data: %w", err)
	}

	err = c.parseResource(resourceData)
	if err != nil {
		return nil, err
	}

	c.BestNodes, err = getBestNodes(setupCtx, c.NodeGroups, c.underlayDialer.DialContext, c.tlsKeyLogWriter)
	if err != nil {
		return nil, err
	}
	if err := setupCtx.Err(); err != nil {
		return nil, err
	}

	err = c.getIP(setupCtx)
	if err != nil {
		return nil, err
	}
	c.underlayDialer.ExcludeIP(c.ip)

	if err := setupCtx.Err(); err != nil {
		return nil, err
	}
	l3Tunnel, err := NewL3Tunnel(c)
	if err != nil {
		return nil, fmt.Errorf("failed to create L3 tunnel: %v", err)
	}
	c.l3TunnelMu.Lock()
	c.l3Tunnel = l3Tunnel
	c.l3TunnelMu.Unlock()
	if options.SaveClientData != nil {
		if err := options.SaveClientData(authData); err != nil {
			return nil, fmt.Errorf("failed to save client data: %w", err)
		}
	}
	sess.SetContext(c.lifecycleCtx)
	if options.SessionRefreshInterval > 0 {
		c.startSessionRefresh(sess.Refresh, clientAuthData, options.SaveClientData, options.SessionRefreshInterval)
	}

	if options.BestNodesRefreshInterval > 0 {
		c.startWorker(func() { c.updateBestNodes(c.lifecycleCtx, options.BestNodesRefreshInterval) })
	}

	success = true
	return authData, nil
}

func resolveServerVersionInfo(cached, fetched []byte, fetchErr error) ([]byte, error) {
	if fetchErr == nil {
		return fetched, nil
	}
	if len(cached) == 0 {
		return nil, fmt.Errorf("failed to acquire aTrust server manifest: %w", fetchErr)
	}
	return cached, nil
}

func buildConnectionID(deviceID string) string {
	sum := md5.Sum([]byte(deviceID))
	return fmt.Sprintf("%X-%d", sum, time.Now().UnixMicro())
}
