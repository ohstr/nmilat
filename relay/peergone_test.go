package relay

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestPeerGone(t *testing.T) {
	wrap := func(errno error) error {
		return &net.OpError{Op: "write", Net: "tcp", Err: os.NewSyscallError("write", errno)}
	}
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"broken pipe":      {wrap(syscall.EPIPE), true},
		"connection reset": {wrap(syscall.ECONNRESET), true},
		"eof":              {io.EOF, true},
		"timeout":          {os.ErrDeadlineExceeded, false},
		"other":            {errors.New("boom"), false},
	} {
		if got := peerGone(tc.err); got != tc.want {
			t.Errorf("%s: peerGone = %v, want %v", name, got, tc.want)
		}
	}
}
