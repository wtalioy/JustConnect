package bridge

import (
	"context"
	"encoding/json"
	"math"
	"sync"
	"time"

	"github.com/wtalioy/JustConnect/corelib"
	"github.com/wtalioy/JustConnect/corelib/policy"
)

// Runner returns only after its resources and goroutines have stopped.
type Runner func(context.Context, Config, *Session) Status

type Engine struct {
	mu      sync.Mutex
	next    uint64
	handles map[uint64]*Session
	active  *Session
	run     Runner
}

func New(run Runner) *Engine {
	if run == nil {
		// A transport-only engine has no protocol runner.
		run = func(context.Context, Config, *Session) Status { return Unsupported }
	}
	return &Engine{handles: make(map[uint64]*Session), run: run}
}

type event struct {
	SchemaVersion int                  `json:"schema_version"`
	Generation    uint64               `json:"generation,string"`
	Sequence      uint64               `json:"sequence,string"`
	Type          string               `json:"type"`
	State         string               `json:"state,omitempty"`
	Status        Status               `json:"status"`
	Message       string               `json:"message,omitempty"`
	Code          string               `json:"code,omitempty"`
	RequestID     uint64               `json:"request_id,omitempty,string"`
	Challenge     *Challenge           `json:"challenge,omitempty"`
	Methods       []AuthMethod         `json:"methods,omitempty"`
	Action        string               `json:"action,omitempty"`
	Cache         *AuthenticationCache `json:"cache,omitempty"`
	Stage         string               `json:"stage,omitempty"`
	Result        string               `json:"result,omitempty"`
	ObservedAt    string               `json:"observed_at,omitempty"`
	Exclude       bool                 `json:"exclude,omitempty"`
	Addresses     []string             `json:"addresses,omitempty"`
}

type AuthenticationCache struct {
	Account string `json:"account"`
	Data    []byte `json:"data"`
}

type queued struct {
	data           []byte
	request        uint64
	diagnostic     bool
	authentication bool
	cacheAction    string
	stage          string
}

type pending struct {
	id        uint64
	ctx       context.Context
	challenge Challenge
	delivered bool
	response  chan Response
}

type Session struct {
	mu               sync.Mutex
	dnsRoutes        *pendingDNSRoutes
	dnsRouteGate     chan struct{}
	protocol         *corelib.Session
	generation       uint64
	sequence         uint64
	nextRequest      uint64
	running          bool
	ctx              context.Context
	unreadAuth       bool
	ready            bool
	stopping         bool
	destroying       bool
	destroyed        bool
	cancel           context.CancelFunc
	done             chan struct{}
	changed          chan struct{}
	queue            []queued
	diagnostics      int
	auth             *pending
	policy           *policy.ProtectionPolicy
	policyRevision   uint64
	connectOperation bool
	coexistence      []byte
	resources        []byte
	resourcesStatus  Status
}

func (s *Session) notify() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// State, authentication, terminal and at most two cache events use reserved slots.
func (s *Session) push(e event) Status {
	s.sequence++
	e.SchemaVersion, e.Generation, e.Sequence = ABIVersion, s.generation, s.sequence
	data, err := json.Marshal(e)
	if err != nil || len(data) > MaxOutput {
		s.sequence--
		return Limit
	}
	s.queue = append(s.queue, queued{data: data, request: e.RequestID, diagnostic: e.Type == "diagnostic", authentication: e.Type == "authentication", cacheAction: e.Action, stage: e.Stage})
	s.notify()
	return OK
}

func (e *Engine) Create(abi uint32) (uint64, Status) {
	if abi != ABIVersion {
		return 0, ABIMismatch
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.handles) >= MaxHandles || e.next == math.MaxUint64 {
		return 0, Limit
	}
	e.next++
	e.handles[e.next] = &Session{changed: make(chan struct{}), dnsRouteGate: make(chan struct{}, 1)}
	return e.next, OK
}

func (e *Engine) lookup(handle uint64) *Session {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.handles[handle]
}

func (e *Engine) Start(handle uint64, input []byte) (uint64, Status) {
	config, status := ParseConfig(input)
	if status != OK {
		return 0, status
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.handles[handle]
	if s == nil {
		return 0, InvalidHandle
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.active != nil || s.destroying || len(s.queue) != 0 {
		return 0, Busy
	}
	if s.generation == math.MaxUint64 {
		return 0, Limit
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.generation++
	s.sequence = 0
	s.running, s.ready, s.stopping = true, false, false
	s.ctx, s.cancel, s.done = ctx, cancel, make(chan struct{})
	s.auth = nil
	s.policy, s.policyRevision, s.connectOperation = config.initialPolicy, 0, config.Operation != "auth_methods"
	s.resources, s.resourcesStatus = nil, Busy
	s.coexistence = nil
	s.push(event{Type: "state", State: "starting"})
	e.active = s
	go e.execute(ctx, config, s)
	return s.generation, OK
}

func (e *Engine) execute(ctx context.Context, config Config, s *Session) {
	status := Internal
	defer func() {
		// Panic values may contain credentials, so only a fixed error crosses the ABI.
		if recover() != nil {
			status = Internal
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.stopping && status != Internal {
			status = Cancelled
		}
		switch status {
		case OK, Timeout, Unsupported, Cancelled, Limit, Internal, AuthMethodChanged, TLSTrust, TLSProtocol, NetworkFailure, AuthUnsupported, CredentialsRequired, SessionInvalid, PermissionDenied:
		default:
			status = Internal
		}
		s.auth = nil
		s.cancel()
		s.running = false
		s.resources = nil
		s.push(event{Type: "terminal", Status: status, Message: status.Message()})
		e.active = nil
		close(s.done)
	}()
	status = e.run(ctx, config, s)
}

func (s *Session) Ready() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.stopping {
		return Cancelled
	}
	if s.ready || s.auth != nil || s.unreadAuth {
		return Busy
	}
	if s.sequence >= math.MaxUint64-1 {
		return Limit
	}
	s.ready = true
	s.push(event{Type: "state", State: "ready"})
	return OK
}

func (s *Session) SaveAuthenticationCache(account string, data []byte) Status {
	if account == "" || len(account) > MaxUsername || len(data) == 0 || len(data) > MaxAuthCache {
		return Limit
	}
	return s.cacheEvent(event{Type: "authentication_cache", Action: "save", Cache: &AuthenticationCache{Account: account, Data: data}})
}

func (s *Session) InvalidateAuthenticationCache() Status {
	return s.cacheEvent(event{Type: "authentication_cache", Action: "invalidate"})
}

func (s *Session) cacheEvent(e event) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.stopping {
		return Cancelled
	}
	if s.sequence >= math.MaxUint64-1 {
		return Limit
	}
	// A rejected session discards pending old saves; later saves follow invalidation.
	kept := s.queue[:0]
	for _, item := range s.queue {
		if item.cacheAction == "" || (e.Action == "save" && item.cacheAction == "invalidate") {
			kept = append(kept, item)
		}
	}
	clear(s.queue[len(kept):])
	s.queue = kept
	return s.push(e)
}

// Observe coalesces each maintenance stage, independently of the diagnostic budget.
func (s *Session) Observe(stage, result string) Status {
	switch stage {
	case "authentication", "restore", "renewal", "traffic", "nodes", "tunnel":
	default:
		return InvalidArgument
	}
	switch result {
	case "running", "succeeded", "failed", "required", "disabled", "unavailable", "unknown":
	default:
		return InvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.stopping {
		return Cancelled
	}
	if s.sequence >= math.MaxUint64-1 {
		return Limit
	}
	kept := s.queue[:0]
	for _, item := range s.queue {
		if item.stage != stage {
			kept = append(kept, item)
		}
	}
	clear(s.queue[len(kept):])
	s.queue = kept
	return s.push(event{Type: "observation", Stage: stage, Result: result, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)})
}

// Diagnostic accepts stable codes, never arbitrary server responses or credentials.
func (s *Session) Diagnostic(code string) Status {
	switch code {
	case "local_controller_real_dns", "local_controller_unavailable", "local_controller_ambiguous",
		"transport_connected", "authentication_started", "keepalive_retry", "anti_mitm_failed", "persistence_failed", "manifest_cached", "auth_detail_unavailable",
		"tls_authentication_failed", "tls_resources_failed", "tls_node_probe_failed", "tls_ip_tunnel_failed",
		"tls_unknown_authority", "tls_hostname_mismatch", "tls_certificate_time_invalid", "tls_certificate_invalid",
		"tls_peer_chain_leaf_only", "tls_peer_self_signed", "tls_node_verification_disabled":
	default:
		return InvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.stopping {
		return Cancelled
	}
	if s.diagnostics >= MaxDiagnostics || s.sequence >= math.MaxUint64-1 {
		return Limit
	}
	s.diagnostics++
	s.push(event{Type: "diagnostic", Code: code})
	return OK
}

func (s *Session) Authenticate(ctx context.Context, challenge Challenge) (Response, Status) {
	return s.authenticate(ctx, challenge, time.Duration(MaxAuthWaitMS)*time.Millisecond)
}

func (s *Session) authenticate(ctx context.Context, challenge Challenge, wait time.Duration) (Response, Status) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	if ctx.Err() == context.DeadlineExceeded {
		return Response{}, Timeout
	}
	if ctx.Err() != nil {
		return Response{}, Cancelled
	}
	if !challenge.valid() {
		return Response{}, InvalidArgument
	}
	s.mu.Lock()
	if !s.running || s.stopping {
		s.mu.Unlock()
		return Response{}, Cancelled
	}
	if s.auth != nil || s.unreadAuth {
		s.mu.Unlock()
		return Response{}, Busy
	}
	if s.nextRequest == math.MaxUint64 || s.sequence >= math.MaxUint64-1 {
		s.mu.Unlock()
		return Response{}, Limit
	}
	s.nextRequest++
	p := &pending{id: s.nextRequest, ctx: ctx, challenge: challenge, response: make(chan Response, 1)}
	// The serialized event owns the image; no caller slice is retained.
	s.push(event{Type: "authentication", RequestID: p.id, Challenge: &challenge})
	p.challenge.Image = nil
	s.auth, s.unreadAuth = p, true
	stopped := s.ctx.Done()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.auth == p {
			s.auth = nil
		}
		s.mu.Unlock()
	}()
	var response Response
	select {
	case response = <-p.response:
	case <-ctx.Done():
	case <-stopped:
	}
	select {
	case <-stopped:
		return Response{}, Cancelled
	default:
	}
	if ctx.Err() == context.DeadlineExceeded {
		return Response{}, Timeout
	}
	if ctx.Err() != nil || response.Action == "cancel" {
		return Response{}, Cancelled
	}
	return response, OK
}

func (e *Engine) Respond(handle uint64, input []byte) Status {
	var response Response
	if !decode(input, &response) || response.SchemaVersion != ABIVersion {
		return InvalidArgument
	}
	s := e.lookup(handle)
	if s == nil {
		return InvalidHandle
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return InvalidHandle
	}
	p := s.auth
	if !s.running || s.stopping || p == nil || p.ctx.Err() != nil || !p.delivered ||
		response.Generation != s.generation || response.RequestID != p.id {
		return StaleRequest
	}
	if !response.valid(p.challenge) {
		return InvalidArgument
	}
	s.auth = nil
	p.response <- response
	return OK
}

func (e *Engine) Read(handle uint64, capacity uint32, waitMS uint32) ([]byte, uint32, Status) {
	if capacity > MaxOutput || waitMS > MaxWaitMS {
		return nil, 0, InvalidArgument
	}
	s := e.lookup(handle)
	if s == nil {
		return nil, 0, InvalidHandle
	}
	timer := time.NewTimer(time.Duration(waitMS) * time.Millisecond)
	defer timer.Stop()
	for {
		s.mu.Lock()
		if s.destroyed {
			s.mu.Unlock()
			return nil, 0, InvalidHandle
		}
		if len(s.queue) != 0 {
			item := s.queue[0]
			length := uint32(len(item.data))
			if capacity < length {
				s.mu.Unlock()
				return nil, length, BufferTooSmall
			}
			s.queue[0] = queued{}
			s.queue = s.queue[1:]
			if item.diagnostic {
				s.diagnostics--
			}
			if s.dnsRoutes != nil && item.request == s.dnsRoutes.id {
				s.dnsRoutes.delivered = true
			}
			if item.authentication {
				s.unreadAuth = false
			}
			if s.auth != nil && item.request == s.auth.id {
				s.auth.delivered = true
			}
			s.mu.Unlock()
			return item.data, length, OK
		}
		if s.stopping && s.running {
			s.mu.Unlock()
			return nil, 0, Cancelled
		}
		if (s.generation != 0 || s.stopping) && !s.running {
			s.mu.Unlock()
			return nil, 0, End
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-timer.C:
			return nil, 0, Timeout
		}
	}
}

func (e *Engine) stop(handle uint64, waitMS uint32, destroy bool) Status {
	if waitMS > MaxWaitMS {
		return InvalidArgument
	}
	e.mu.Lock()
	s := e.handles[handle]
	if s == nil {
		known := handle != 0 && handle <= e.next
		e.mu.Unlock()
		if destroy && known {
			return OK
		}
		return InvalidHandle
	}
	s.mu.Lock()
	if destroy {
		s.destroying = true
	}
	done := s.done
	s.stopping = true
	if s.running {
		s.cancel()
	}
	s.notify()
	s.mu.Unlock()
	e.mu.Unlock()
	if done != nil {
		timer := time.NewTimer(time.Duration(waitMS) * time.Millisecond)
		defer timer.Stop()
		select {
		case <-done:
		default:
			select {
			case <-done:
			case <-timer.C:
				return Timeout
			}
		}
	}
	if destroy {
		e.mu.Lock()
		defer e.mu.Unlock()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.destroyed = true
		s.queue, s.auth = nil, nil
		s.notify()
		delete(e.handles, handle)
	}
	return OK
}

func (e *Engine) Stop(handle uint64, waitMS uint32) Status    { return e.stop(handle, waitMS, false) }
func (e *Engine) Destroy(handle uint64, waitMS uint32) Status { return e.stop(handle, waitMS, true) }

func (s *Session) AuthMethods(methods []AuthMethod) Status {
	if len(methods) > MaxAuthMethods {
		return Limit
	}
	for _, m := range methods {
		if len(m.AuthID) > MaxDomain || len(m.SubType) > MaxDomain || len(m.Type) > MaxDomain || len(m.Domain) > MaxDomain || len(m.Name) > MaxAuthMethodName || len(m.LoginURL) > MaxURL {
			return Limit
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.stopping {
		return Cancelled
	}
	if s.ready || s.auth != nil || s.sequence >= math.MaxUint64-1 {
		return Busy
	}
	status := s.push(event{Type: "auth_methods", Methods: methods})
	if status == OK {
		s.ready = true
	}
	return status
}
