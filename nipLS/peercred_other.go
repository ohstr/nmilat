//go:build !linux

package nipLS

import "net"

// PeerCredSupported reports whether peer uid/gid checks work here.
const PeerCredSupported = false

func peerCredOf(net.Conn) Peer { return Peer{} }
