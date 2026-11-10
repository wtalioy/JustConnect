package service

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"github.com/wtalioy/JustConnect/corelib/internal/socksudp"
)

const maxSOCKSUDPFlows = 256

type socksUDPFlow struct {
	net.Conn
	idle *udpIdleTimer
}

func (p *Listeners) handleSOCKSUDP(ctx context.Context, writer io.Writer, request *socks5.Request, timeout time.Duration) error {
	local, localOK := request.LocalAddr.(*net.TCPAddr)
	peer, peerOK := request.RemoteAddr.(*net.TCPAddr)
	if !localOK || !peerOK {
		return socks5.SendReply(writer, statute.RepServerFailure, nil)
	}
	peerIP, validPeer := netip.AddrFromSlice(peer.IP)
	if !validPeer {
		return socks5.SendReply(writer, statute.RepServerFailure, nil)
	}
	peerIP = peerIP.Unmap()
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP})
	if err != nil {
		_ = socks5.SendReply(writer, statute.RepServerFailure, nil)
		return err
	}
	p.mu.Lock()
	if p.closed.Load() {
		p.mu.Unlock()
		_ = listener.Close()
		return net.ErrClosed
	}
	p.connections[listener] = struct{}{}
	p.mu.Unlock()
	ctx, cancel := joinedContext(ctx, p.ctx)
	var mu sync.Mutex
	flows := make(map[string]*socksUDPFlow)
	var workers sync.WaitGroup
	start := func(work func()) {
		workers.Add(1)
		go func() { defer workers.Done(); defer p.recoverWorker(); work() }()
	}
	defer func() {
		cancel()
		_ = listener.Close()
		mu.Lock()
		for _, conn := range flows {
			_ = conn.Close()
		}
		mu.Unlock()
		workers.Wait()
		p.mu.Lock()
		delete(p.connections, listener)
		p.mu.Unlock()
	}()
	// Register cleanup before replying; the peer may disconnect during the reply.
	if err := socks5.SendReply(writer, statute.RepSuccess, listener.LocalAddr()); err != nil {
		return err
	}
	start(func() {
		buf := make([]byte, maxUDPPacket)
		var source netip.AddrPort
		for {
			n, sender, err := listener.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if sender.Addr().Unmap().WithZone("") != peerIP || (request.DestAddr.Port != 0 && int(sender.Port()) != request.DestAddr.Port) {
				continue
			}
			if source.IsValid() && source != sender {
				continue
			}
			packet, err := socksudp.Parse(buf[:n])
			if err != nil {
				continue
			}
			if !source.IsValid() {
				source = sender
			}
			encodedDestination := buf[:n-len(packet.Data)]
			mu.Lock()
			target := flows[string(encodedDestination)]
			full := len(flows) >= maxSOCKSUDPFlows
			mu.Unlock()
			if target == nil {
				if full {
					continue
				}
				conn, err := p.dial(ctx, "udp", packet.DstAddr.String())
				if err != nil {
					continue
				}
				mu.Lock()
				if ctx.Err() != nil {
					mu.Unlock()
					_ = conn.Close()
					return
				}
				// Own the validated wire header once; packet storage is reused on the next read.
				key := string(encodedDestination)
				remote := &socksUDPFlow{Conn: conn}
				closeFlow := sync.OnceFunc(func() {
					mu.Lock()
					if flows[key] == remote {
						delete(flows, key)
					}
					mu.Unlock()
					_ = conn.Close()
				})
				remote.idle = newUDPIdleTimer(timeout, closeFlow)
				flows[key] = remote
				target = remote
				mu.Unlock()
				replyTo := source
				start(func() {
					defer closeFlow()
					defer remote.idle.stop()
					reply := make([]byte, maxUDPPacket)
					copy(reply, key)
					for {
						n, err := remote.Read(reply[len(key):])
						if err != nil || !remote.idle.touch() {
							return
						}
						if _, err := listener.WriteToUDPAddrPort(reply[:len(key)+n], replyTo); err != nil {
							return
						}
					}
				})
			}
			if !target.idle.touch() {
				_ = target.Close()
				continue
			}
			if _, err := target.Write(packet.Data); err != nil {
				_ = target.Close()
			}
		}
	})
	_, err = io.Copy(io.Discard, request.Reader)
	return err
}
