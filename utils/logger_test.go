package utils

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestRecoverPanic_ContainsPanicWithoutExiting(t *testing.T) {
	done := make(chan struct{})

	go func() {
		defer close(done)
		defer RecoverPanic(zerolog.Nop())
		panic("boom")
	}()

	<-done // if RecoverPanic didn't contain the panic, this goroutine would crash the test binary.
}

func TestRecoverPanic_NoPanicIsNoOp(t *testing.T) {
	defer RecoverPanic(zerolog.Nop())
	// Nothing to recover; RecoverPanic should simply do nothing.
}
