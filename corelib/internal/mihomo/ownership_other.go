//go:build darwin || windows

package mihomo

import (
	"context"
	"net/netip"

	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
)

func needsListenerProof(context.Context, model.Process, netip.AddrPort) bool { return false }
func validListenerProof(context.Context, model.Process, netip.AddrPort, *ListenerProof) bool {
	return false
}

func localListenerProof(ctx context.Context, process model.Process, address netip.AddrPort) (*ListenerProof, bool) {
	return nil, ownsTCP(ctx, process, address)
}
