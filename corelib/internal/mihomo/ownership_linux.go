//go:build linux

package mihomo

import (
	"context"
	"net/netip"

	native "github.com/wtalioy/JustConnect/corelib/internal/mihomo/linux"
	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
)

func needsListenerProof(ctx context.Context, process model.Process, address netip.AddrPort) bool {
	return native.NeedsProof(ctx, process, address)
}
func validListenerProof(ctx context.Context, process model.Process, address netip.AddrPort, proof *ListenerProof) bool {
	return proof != nil && proof.PID == process.PID && proof.Started == process.Started && proof.Endpoint == address.String() && native.ListenerUnchanged(ctx, process, address, proof.Inode)
}

func localListenerProof(ctx context.Context, process model.Process, address netip.AddrPort) (*ListenerProof, bool) {
	inode := native.OwnedListenerInode(ctx, process, address)
	if inode == 0 {
		return nil, false
	}
	return &ListenerProof{PID: process.PID, Started: process.Started, Endpoint: address.String(), Inode: inode}, true
}
