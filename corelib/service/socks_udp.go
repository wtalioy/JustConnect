package service

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

const maxSOCKSUDPFlows = 256
const maxUDPPacket = 1<<16 - 1

func (p *Listeners) handleSOCKSUDP(ctx context.Context, writer io.Writer, request *socks5.Request) error {
	local, localOK := request.LocalAddr.(*net.TCPAddr)
	peer, peerOK := request.RemoteAddr.(*net.TCPAddr)
	if !localOK || !peerOK {
		return socks5.SendReply(writer, statute.RepServerFailure, nil)
	}
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP})
	if err != nil {
		_ = socks5.SendReply(writer, statute.RepServerFailure, nil)
		return err
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = listener.Close()
		return net.ErrClosed
	}
	p.connections[listener] = struct{}{}
	p.mu.Unlock()
	ctx, cancel := joinedContext(ctx, p.ctx)
	var mu sync.Mutex
	flows := make(map[string]net.Conn)
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
		var source *net.UDPAddr
		for {
			n, sender, err := listener.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !sender.IP.Equal(peer.IP) || (request.DestAddr.Port != 0 && sender.Port != request.DestAddr.Port) {
				continue
			}
			if source != nil && source.AddrPort() != sender.AddrPort() {
				continue
			}
			if n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
				continue
			}
			packet, err := statute.ParseDatagram(buf[:n])
			if err != nil {
				continue
			}
			if source == nil {
				source = sender
			}
			destination := packet.DstAddr.String()
			mu.Lock()
			target := flows[destination]
			full := len(flows) >= maxSOCKSUDPFlows
			mu.Unlock()
			if target == nil {
				if full {
					continue
				}
				target, err = p.dial(ctx, "udp", destination)
				if err != nil {
					continue
				}
				mu.Lock()
				if ctx.Err() != nil {
					mu.Unlock()
					_ = target.Close()
					return
				}
				flows[destination] = target
				mu.Unlock()
				header := packet.Header()
				remote := target
				replyTo := source
				start(func() {
					defer remote.Close()
					defer func() {
						mu.Lock()
						if flows[destination] == remote {
							delete(flows, destination)
						}
						mu.Unlock()
					}()
					reply := make([]byte, maxUDPPacket)
					for {
						n, err := remote.Read(reply[len(header):])
						if err != nil {
							return
						}
						copy(reply, header)
						if _, err := listener.WriteToUDP(reply[:len(header)+n], replyTo); err != nil {
							return
						}
					}
				})
			}
			if _, err := target.Write(packet.Data); err != nil {
				_ = target.Close()
			}
		}
	})
	_, err = io.Copy(io.Discard, request.Reader)
	return err
}
