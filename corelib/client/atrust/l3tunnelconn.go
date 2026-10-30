package atrust

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client/atrust/auth"
	"github.com/wtalioy/JustConnect/corelib/internal/zctcpip"
)

const (
	l3Version        = 0x05
	cmdAuthReq       = 0x13
	cmdAuthResp      = 0x93
	cmdDataReq       = 0x14
	cmdDataResp      = 0x94
	cmdHeartbeatReq  = 0x15
	cmdHeartbeatResp = 0x95
	cmdSecondVipResp = 0x96

	defaultHeartbeatInterval  = 5 * time.Second
	defaultHeartbeatMissLimit = 3
	defaultAuthTimeout        = 5 * time.Second
	defaultAuthScanInterval   = 250 * time.Millisecond
	defaultAuthRetryWait      = 10 * time.Second
	defaultAuthMaxAttempts    = 3
	defaultAuthBatchSize      = 64
	authImmediateRetryStatus  = 0x84
	authRetryStatusMin        = 0x85
	authRetryStatusMax        = 0x87
)

var errL3TunnelAuthTimeout = errors.New("l3-tunnel auth timeout")

type dataFrame struct {
	payload []byte
}

var dataFramePool = sync.Pool{
	New: func() any {
		return &dataFrame{payload: make([]byte, 0, 2048)}
	},
}

type clientInfo struct {
	language     string
	onError      func(error)
	sid          string
	sidProvider  func() (string, error)
	deviceID     string
	connectionID string
	username     string
}

func (info clientInfo) currentSID() (string, error) {
	if info.sidProvider != nil {
		return info.sidProvider()
	}
	return info.sid, nil
}

type l3TunnelConn struct {
	addr               string
	tlsConn            *tls.Conn
	reader             *bufio.Reader
	writeMu            sync.Mutex
	incoming           chan []byte
	workers            sync.WaitGroup
	closeOnce          sync.Once
	closeCh            chan struct{}
	conntrackMgr       *conntrackMgr
	signKey            []byte
	info               clientInfo
	onVIP              func([]net.IP)
	heartbeatInterval  time.Duration
	heartbeatMissLimit int32
	heartbeatMisses    int32
	heartbeatHasWrite  uint32
	authWake           chan struct{}
	writeFrameHook     func([]byte) error
	dataStream         []byte
}

type authIP struct {
	Atype    int    `json:"atype"`
	Protocol int    `json:"protocol"`
	DestAddr string `json:"destAddr"`
	DestPort uint16 `json:"destPort"`
	SrcAddr  string `json:"srcAddr"`
	SrcPort  uint16 `json:"srcPort"`
}

type authRequestIP struct {
	Sid           string    `json:"sid"`
	AppID         string    `json:"appId"`
	ProcHash      string    `json:"procHash,omitempty"`
	AppToken      string    `json:"appToken,omitempty"`
	URL           string    `json:"url"`
	DeviceID      string    `json:"deviceId"`
	ConnectionID  string    `json:"connectionId"`
	RCAppliedInfo int       `json:"rcAppliedInfo"`
	Lang          string    `json:"lang"`
	Env           *trustEnv `json:"env,omitempty"`
	ConntrackHash uint64    `json:"conntrackHash"`
	IP            authIP    `json:"ip"`
	Domain        string    `json:"domain,omitempty"`
	XRequestSig   string    `json:"xRequestSig"`
}

type authResponseIP struct {
	Code    int64              `json:"code"`
	Message string             `json:"message"`
	Data    authResponseIPData `json:"data"`
}

type authResponseIPData struct {
	VipType       string `json:"vipType,omitempty"`
	Vip6Type      string `json:"vip6Type,omitempty"`
	Vip4Type      string `json:"vip4Type,omitempty"`
	ConntrackHash uint64 `json:"conntrackHash"`
	ConnectToken  string `json:"connectToken,omitempty"`
	IP            authIP `json:"ip"`
}

type authRequestSID struct {
	Sid string `json:"sid"`
}

type authResponseSID struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
	Data    struct {
		DeviceID string `json:"deviceId"`
	} `json:"data"`
}

type trustEnv struct {
	Application struct {
		Runtime struct {
			Process struct {
				Name             string `json:"name"`
				DigitalSignature string `json:"digital_signature"`
				Platform         string `json:"platform"`
				Fingerprint      string `json:"fingerprint"`
				Description      string `json:"description"`
				Path             string `json:"path"`
				Version          string `json:"version"`
				SecurityEnv      string `json:"security_env"`
			} `json:"process"`
			ProcessTrusted string `json:"process_trusted"`
		} `json:"runtime"`
	} `json:"application"`
}

type packetMeta struct {
	atype   int
	proto   int
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
	key     string
}

type frame struct {
	cmd     byte
	status  byte
	payload []byte
}

func newL3TunnelConn(ctx context.Context, dialTLS func(context.Context, string, string) (*tls.Conn, error), addr string, info clientInfo, signKeyHex string, conntrackMgr *conntrackMgr, onVIP func([]net.IP)) (*l3TunnelConn, error) {
	tlsConn, err := dialTLS(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	signKey, err := hex.DecodeString(signKeyHex)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("invalid sign key: %w", err)
	}

	c := &l3TunnelConn{
		addr:               addr,
		tlsConn:            tlsConn,
		reader:             bufio.NewReader(tlsConn),
		incoming:           make(chan []byte, 128),
		closeCh:            make(chan struct{}),
		conntrackMgr:       conntrackMgr,
		signKey:            signKey,
		info:               info,
		onVIP:              onVIP,
		heartbeatInterval:  defaultHeartbeatInterval,
		heartbeatMissLimit: defaultHeartbeatMissLimit,
		authWake:           make(chan struct{}, 1),
	}
	if err := c.withContextDeadline(ctx, c.authTunnel); err != nil {
		_ = c.Close()
		return nil, err
	}

	c.startWorker(c.authLoop)
	c.startWorker(c.readLoop)
	c.startWorker(c.heartbeatLoop)
	return c, nil
}

func (c *l3TunnelConn) withContextDeadline(ctx context.Context, operation func() error) error {
	stopCancel := context.AfterFunc(ctx, func() { _ = c.tlsConn.Close() })
	defer stopCancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		err := operation()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if err := c.tlsConn.SetDeadline(deadline); err != nil {
		return err
	}
	operationErr := operation()
	if ctx.Err() != nil {
		operationErr = ctx.Err()
	}
	clearErr := c.tlsConn.SetDeadline(time.Time{})
	if operationErr != nil {
		return operationErr
	}
	return clearErr
}

func (c *l3TunnelConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closeCh)
		if c.tlsConn != nil {
			err = c.tlsConn.Close()
		}
	})
	return err
}

func (c *l3TunnelConn) readLoop() {
	for {
		fr, err := c.readFrame()
		if err != nil {

			_ = c.Close()
			return
		}

		switch fr.cmd {
		case cmdDataResp:
			c.dataStream = append(c.dataStream, fr.payload...)
			packets, remaining, err := splitIncomingIPPackets(c.dataStream)
			if err != nil {

				_ = c.Close()
				return
			}
			c.dataStream = remaining

			for _, pkt := range packets {
				c.refreshIncomingConntrack(pkt)
				if !c.deliverIncoming(pkt) {
					return
				}
			}
		case cmdAuthResp:

			c.handleAuthResp(fr.status, fr.payload)
		case cmdSecondVipResp:

			c.handleSecondVipResp(fr.status, fr.payload)
		case cmdHeartbeatResp:

			atomic.StoreUint32(&c.heartbeatHasWrite, 0)
			atomic.StoreInt32(&c.heartbeatMisses, 0)
		default:

		}
	}
}

func (c *l3TunnelConn) refreshIncomingConntrack(packet []byte) {
	meta, err := buildPacketMeta(packet)
	if err != nil {
		return
	}
	meta.srcIP, meta.dstIP = meta.dstIP, meta.srcIP
	meta.srcPort, meta.dstPort = meta.dstPort, meta.srcPort
	c.conntrackMgr.observePacket(connTrackKey(meta), packet, true)
}

func (c *l3TunnelConn) deliverIncoming(packet []byte) bool {
	select {
	case <-c.closeCh:
		return false
	default:
	}
	select {
	case c.incoming <- packet:
		return true
	case <-c.closeCh:
		return false
	default:

		return true
	}
}

func (c *l3TunnelConn) heartbeatLoop() {
	interval := c.heartbeatInterval
	if interval <= 0 {
		interval = defaultHeartbeatInterval
	}
	missLimit := c.heartbeatMissLimit
	if missLimit <= 0 {
		missLimit = defaultHeartbeatMissLimit
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.conntrackMgr.removeExpired()
			if atomic.SwapUint32(&c.heartbeatHasWrite, 0) != 0 {
				atomic.StoreInt32(&c.heartbeatMisses, 0)
				continue
			}
			misses := atomic.LoadInt32(&c.heartbeatMisses)
			if misses >= missLimit {

				_ = c.Close()
				return
			}
			atomic.AddInt32(&c.heartbeatMisses, 1)
			if !c.sendHeartbeat() {
				return
			}
		case <-c.closeCh:
			return
		}
	}
}

func (c *l3TunnelConn) sendHeartbeat() bool {
	if err := c.writeFrame([]byte{l3Version, cmdHeartbeatReq, 0x00, 0x00}); err != nil {

		_ = c.Close()
		return false
	}
	return true
}

func (c *l3TunnelConn) readFrame() (frame, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return frame{}, err
	}
	if header[0] != l3Version {

		return frame{}, fmt.Errorf("unexpected L3 tunnel version 0x%02x", header[0])
	}

	cmd := header[1]
	switch cmd {
	case cmdAuthResp, cmdSecondVipResp:
		statusLen := make([]byte, 3)
		if _, err := io.ReadFull(c.reader, statusLen); err != nil {
			return frame{}, err
		}
		status := statusLen[0]
		payloadLen := int(binary.BigEndian.Uint16(statusLen[1:3]))
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return frame{}, err
		}

		return frame{cmd: cmd, status: status, payload: payload}, nil
	case cmdDataResp, cmdHeartbeatResp:
		payload, err := readDataRespPayload(c.reader)
		if err != nil {
			return frame{}, err
		}

		return frame{cmd: cmd, payload: payload}, nil
	default:

		return frame{}, fmt.Errorf("unexpected L3 tunnel command 0x%02x", cmd)
	}
}

func (c *l3TunnelConn) ReadPacket() ([]byte, error) {
	select {
	case pkt := <-c.incoming:
		return pkt, nil
	case <-c.closeCh:
		return nil, io.EOF
	}
}

func (c *l3TunnelConn) WritePacket(meta packetMeta, appID, nodeGroupID string, pkt []byte) error {
	ct := c.conntrackMgr.getOrCreate(meta.key, appID, nodeGroupID)
	c.conntrackMgr.observePacket(meta.key, pkt, false)
	ct.sendMu.Lock()
	defer ct.sendMu.Unlock()

	token, authErr, authenticated := c.conntrackMgr.authResult(ct)
	if authenticated {
		if authErr != nil {
			return authErr
		}
		return c.writeAuthenticatedPacket(ct, meta, appID, nodeGroupID, token, pkt)
	}

	_, err := c.conntrackMgr.cachePacket(ct, meta, pkt)
	if errors.Is(err, errPendingPacketCacheFull) {

		return nil
	}
	if err != nil {
		return err
	}
	c.notifyAuth()
	return nil
}

func (c *l3TunnelConn) writeAuthenticatedPacket(ct *conntrack, meta packetMeta, appID, nodeGroupID, token string, pkt []byte) error {
	if len(token) > 0xFF {
		return fmt.Errorf("l3-tunnel connect token too long: %d", len(token))
	}
	frame := getDataPayload(token, pkt)
	defer putDataPayload(frame)
	payload := frame.payload

	err := c.writeFrame(payload)
	return err
}

func (c *l3TunnelConn) notifyAuth() {
	select {
	case c.authWake <- struct{}{}:
	default:
	}
}

func (c *l3TunnelConn) authLoop() {
	ticker := time.NewTicker(defaultAuthScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.authWake:
			if !c.dispatchPendingAuth() {
				return
			}
		case now := <-ticker.C:
			c.conntrackMgr.expireAuth(now, errL3TunnelAuthTimeout)
			if !c.dispatchPendingAuth() {
				return
			}
		case <-c.closeCh:
			return
		}
	}
}

func (c *l3TunnelConn) dispatchPendingAuth() bool {
	for {
		jobs, more := c.conntrackMgr.nextAuthBatch(defaultAuthBatchSize)
		for _, job := range jobs {
			if err := c.sendAuthRequest(job.conntrack, job.meta); err != nil {
				c.conntrackMgr.markAuth(job.conntrack.authID, "", err)
				_ = c.Close()
				return false
			}
			c.conntrackMgr.markAuthSent(job.conntrack.authID, time.Now().Add(defaultAuthTimeout))
		}
		if !more {
			return true
		}
	}
}

func (c *l3TunnelConn) sendAuthRequest(ct *conntrack, meta packetMeta) error {
	req, err := buildAuthRequest(c.info, c.signKey, meta, ct)
	if err != nil {
		return err
	}

	payload := make([]byte, 0, 4+len(req))
	payload = append(payload, l3Version, cmdAuthReq)
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(req)))
	payload = append(payload, lenBytes...)
	payload = append(payload, req...)
	return c.writeFrame(payload)
}

func (c *l3TunnelConn) handleAuthResp(status byte, payload []byte) {
	var resp authResponseIP
	if err := json.Unmarshal(payload, &resp); err != nil {
		c.markAuthErrorFromPayload(payload, err)
		return
	}
	if resp.Code == 10000004 || resp.Code == 75500002 {
		c.report(auth.ErrSessionInvalid)
		_ = c.Close()
		return
	}
	ct := c.conntrackMgr.getByID(resp.Data.ConntrackHash)
	if ct == nil {
		ct = c.conntrackMgr.getByAuthResponseIP(resp.Data.IP)
	}
	if ct == nil {
		c.markAuthErrorFromPayload(payload, fmt.Errorf("missing conntrack hash"))
		return
	}
	authID := ct.authID
	if status != 0 {
		if status == authImmediateRetryStatus {
			c.scheduleAuthRetry(authID, 0)
			return
		}
		if isRetryableAuthResponse(status, resp) {
			c.scheduleAuthRetry(authID, defaultAuthRetryWait)
			return
		}
		c.completeAuthentication(authID, "", fmt.Errorf("auth status %d: %s", status, resp.Message))
		return
	}

	token := resp.Data.ConnectToken

	c.completeAuthentication(authID, token, nil)
}

func isRetryableAuthResponse(status byte, resp authResponseIP) bool {
	return status >= authRetryStatusMin && status <= authRetryStatusMax
}

func (c *l3TunnelConn) scheduleAuthRetry(authID uint64, delay time.Duration) {
	if c.conntrackMgr.retryAuth(authID, delay) {

		c.notifyAuth()
	}
}

func (c *l3TunnelConn) handleSecondVipResp(status byte, payload []byte) {
	if status != 0 {

		return
	}
	ips := extractVIPs(payload)
	if len(ips) == 0 {
		return
	}
	if c.onVIP != nil {
		c.onVIP(ips)
	}
}

func (c *l3TunnelConn) markAuthErrorFromPayload(payload []byte, err error) {
	var resp authResponseIP
	if json.Unmarshal(payload, &resp) == nil && resp.Data.ConntrackHash != 0 {
		c.completeAuthentication(resp.Data.ConntrackHash, "", err)
	}
}

func (c *l3TunnelConn) completeAuthentication(authID uint64, token string, authErr error) {
	ct := c.conntrackMgr.getByID(authID)
	if ct == nil {
		return
	}
	ct.sendMu.Lock()
	defer ct.sendMu.Unlock()
	_, packets := c.conntrackMgr.completeAuth(authID, token, authErr)
	if authErr != nil {
		return
	}
	for _, packet := range packets {
		if err := c.writeAuthenticatedPacket(ct, ct.authMeta, ct.appID, ct.nodeGroupID, token, packet); err != nil {

			_ = c.Close()
			return
		}
	}
}

func (c *l3TunnelConn) writeFrame(data []byte) error {
	if c.writeFrameHook != nil {
		err := c.writeFrameHook(data)
		if err == nil {
			atomic.StoreUint32(&c.heartbeatHasWrite, 1)
		}
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	n, err := c.tlsConn.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	if err == nil {
		atomic.StoreUint32(&c.heartbeatHasWrite, 1)
	}
	return err
}

func (c *l3TunnelConn) writeRaw(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	_, err := c.tlsConn.Write(data)
	return err
}

func buildAuthRequest(info clientInfo, signKey []byte, meta packetMeta, ct *conntrack) ([]byte, error) {
	sid, err := info.currentSID()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s:%s:%d", protoName(meta.proto), meta.dstIP.String(), meta.dstPort)
	env := defaultEnv(info)

	req := authRequestIP{
		Sid:           sid,
		AppID:         ct.appID,
		URL:           url,
		DeviceID:      info.deviceID,
		ConnectionID:  info.connectionID,
		Env:           env,
		ConntrackHash: ct.authID,
		Lang:          protocolLanguage(info.language),
		IP: authIP{
			Atype:    authIPType(meta.atype),
			Protocol: meta.proto,
			DestAddr: meta.dstIP.String(),
			DestPort: meta.dstPort,
			SrcAddr:  meta.srcIP.String(),
			SrcPort:  meta.srcPort,
		},
		ProcHash:    env.Application.Runtime.Process.Fingerprint,
		XRequestSig: "",
	}

	unsigned, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	sig := calcXRequestSig(signKey, unsigned)
	req.XRequestSig = sig
	return json.Marshal(req)
}

func defaultEnv(info clientInfo) *trustEnv {
	procPath := "/usr/bin/zju-connect"
	procName := "zju-connect"
	fingerprint := fmt.Sprintf("%X", sha256.Sum256([]byte(procPath)))
	platform := strings.Title(runtime.GOOS)
	if platform == "Darwin" {
		platform = "macOS"
	}

	var env trustEnv
	env.Application.Runtime.Process.Name = procName
	env.Application.Runtime.Process.DigitalSignature = "TrustAppClosed"
	env.Application.Runtime.Process.Platform = platform
	env.Application.Runtime.Process.Fingerprint = fingerprint
	env.Application.Runtime.Process.Description = "TrustAppClosed"
	env.Application.Runtime.Process.Path = procPath
	env.Application.Runtime.Process.Version = "TrustAppClosed"
	env.Application.Runtime.Process.SecurityEnv = "normal"
	env.Application.Runtime.ProcessTrusted = "TRUSTED"
	return &env
}

func getDataPayload(token string, packet []byte) *dataFrame {
	frame := dataFramePool.Get().(*dataFrame)
	payload := frame.payload[:0]
	required := 8 + len(token) + len(packet)
	if cap(payload) < required {
		payload = make([]byte, 0, required)
	}
	payload = append(payload, l3Version, cmdDataReq, byte(len(token)))
	payload = append(payload, token...)
	payload = append(payload, 0x00, 0x00, 0x01, 0x00, 0x00)
	binary.BigEndian.PutUint16(payload[len(payload)-2:], uint16(len(packet)))
	payload = append(payload, packet...)
	frame.payload = payload
	return frame
}

func putDataPayload(frame *dataFrame) {
	// Avoid retaining unexpectedly large packets in the process-wide pool.
	if cap(frame.payload) > maxPooledDataPayload {
		return
	}
	frame.payload = frame.payload[:0]
	dataFramePool.Put(frame)
}

const maxPooledDataPayload = 4096

func readDataRespPayload(r *bufio.Reader) ([]byte, error) {
	var lenBytes [2]byte
	if _, err := io.ReadFull(r, lenBytes[:]); err != nil {
		return nil, err
	}
	payload := make([]byte, int(binary.BigEndian.Uint16(lenBytes[:])))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func splitIncomingIPPackets(stream []byte) ([][]byte, []byte, error) {
	var packets [][]byte
	for len(stream) > 0 {
		var packetLen int
		switch stream[0] >> 4 {
		case zctcpip.IPv4Version:
			if len(stream) < 4 {
				return packets, stream, nil
			}
			headerLen := int(stream[0]&0x0f) * 4
			packetLen = int(binary.BigEndian.Uint16(stream[2:4]))
			if headerLen < 20 || packetLen < headerLen {
				return nil, nil, fmt.Errorf("invalid IPv4 packet length %d with header length %d", packetLen, headerLen)
			}
		case 6:
			if len(stream) < 6 {
				return packets, stream, nil
			}
			packetLen = 40 + int(binary.BigEndian.Uint16(stream[4:6]))
		default:
			return nil, nil, fmt.Errorf("unexpected IP version %d", stream[0]>>4)
		}
		if len(stream) < packetLen {
			return packets, stream, nil
		}
		packet := append([]byte(nil), stream[:packetLen]...)
		packets = append(packets, packet)
		stream = stream[packetLen:]
	}
	return packets, nil, nil
}

func (c *l3TunnelConn) authTunnel() error {
	sid, err := c.info.currentSID()
	if err != nil {
		return err
	}
	req, err := json.Marshal(authRequestSID{Sid: sid})
	if err != nil {
		return err
	}

	packet := wrapAuthReqData(req, 1)
	if err := c.writeRaw(packet); err != nil {
		return err
	}

	method := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, method); err != nil {
		return err
	}

	if method[0] != l3Version || method[1] != 0xD0 {
		return fmt.Errorf("l3-tunnel unexpected auth method resp: %02x %02x", method[0], method[1])
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return err
	}

	if header[0] != 0x53 {
		return fmt.Errorf("l3-tunnel unexpected auth resp version: 0x%02x", header[0])
	}
	status := header[1]
	length := int(binary.BigEndian.Uint16(header[2:4]))
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return err
		}
	}

	if len(payload) > 0 {
		var resp authResponseSID
		if err := json.Unmarshal(payload, &resp); err != nil {
			return err
		}
		if resp.Code == 10000004 || resp.Code == 75500002 {
			return auth.ErrSessionInvalid
		}
		if resp.Code != 0 {
			return fmt.Errorf("l3-tunnel tunnel auth failed: %d %s", resp.Code, resp.Message)
		}
	}
	if status != 0 {
		return fmt.Errorf("l3-tunnel tunnel auth status %d", status)
	}

	vipHeader := make([]byte, 4)
	if _, err := io.ReadFull(c.reader, vipHeader); err != nil {
		return err
	}

	dataLen, err := parseInitialVIPHeader(vipHeader)
	if err != nil {
		return err
	}
	vipData := make([]byte, dataLen)
	if _, err := io.ReadFull(c.reader, vipData); err != nil {
		return err
	}

	ips := parseVirtualIPData(vipData)
	if len(ips) > 0 && c.onVIP != nil {
		c.onVIP(ips)
	}
	return nil
}

func wrapAuthReqData(payload []byte, addrType byte) []byte {
	header := make([]byte, 4+len(payload))
	header[0] = 0x53
	header[1] = 0x00
	binary.BigEndian.PutUint16(header[2:4], uint16(len(payload)))
	copy(header[4:], payload)

	buf := make([]byte, 0, 3+len(header)+10)
	buf = append(buf, l3Version, 0x01, 0xD0)
	buf = append(buf, header...)
	buf = append(buf, 0x05, 0x04, 0x00, addrType, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	return buf
}

func parseInitialVIPHeader(header []byte) (int, error) {
	if len(header) != 4 {
		return 0, fmt.Errorf("l3-tunnel invalid vip header length %d", len(header))
	}
	if header[0] != l3Version {
		return 0, fmt.Errorf("l3-tunnel unexpected vip version: %02x", header[0])
	}
	if header[1] != 0 {
		return 0, fmt.Errorf("l3-tunnel vip status %d", header[1])
	}
	switch header[3] {
	case 1:
		return 6, nil
	case 4:
		return 18, nil
	case 5:
		return 22, nil
	default:
		return 0, fmt.Errorf("l3-tunnel unsupported vip address type %d", header[3])
	}
}

func parseVirtualIPData(data []byte) []net.IP {
	var ips []net.IP
	switch len(data) {
	case 6:
		ips = append(ips, net.IPv4(data[0], data[1], data[2], data[3]))
	case 18:
		ips = append(ips, net.IP(data[:16]))
	case 22:
		ips = append(ips, net.IPv4(data[0], data[1], data[2], data[3]))
		ips = append(ips, net.IP(data[4:20]))
	}
	return ips
}

func extractVIPs(payload []byte) []net.IP {
	type virtualIPs struct {
		VIP      string `json:"vip"`
		VIP6     string `json:"vip6"`
		VIPType  any    `json:"vip_type"`
		VIP6Type any    `json:"vip6_type"`
	}
	var resp struct {
		virtualIPs
		Data virtualIPs `json:"data"`
	}
	if err := json.Unmarshal(payload, &resp); err != nil {
		return nil
	}
	values := resp.virtualIPs
	if values.VIP == "" && values.VIP6 == "" {
		values = resp.Data
	}
	ips := make([]net.IP, 0, 2)
	if ip := net.ParseIP(values.VIP); ip != nil && ip.To4() != nil {
		ips = append(ips, ip.To4())
	}
	if ip := net.ParseIP(values.VIP6); ip != nil && ip.To4() == nil {
		ips = append(ips, ip.To16())
	}
	return ips
}

func protoName(proto int) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmp6"
	default:
		return "ip"
	}
}

func authIPType(atype int) int {
	switch atype {
	case 6:
		return 0x86DD
	default:
		return 0x0800
	}
}

func protocolLanguage(language string) string {
	if language == "" {
		return auth.Language
	}
	return language
}

func (c *Client) requestLanguage() string { return protocolLanguage(c.language) }

func (c *l3TunnelConn) report(err error) {
	if c.info.onError != nil {
		c.info.onError(err)
	}
}

func (c *l3TunnelConn) startWorker(work func()) {
	c.workers.Add(1)
	go func() {
		defer c.workers.Done()
		defer func() {
			if recover() != nil {
				c.report(errors.New("L3 worker panicked"))
				_ = c.Close()
			}
		}()
		work()
	}()
}

func (c *l3TunnelConn) Wait() { c.workers.Wait() }
