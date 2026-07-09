package utils

import (
	"os"
	"runtime"
	"strconv"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// RecoverPanic recovers a panic in the calling goroutine and logs it with a
// stack trace through logger. It intentionally does not re-panic or
// terminate the process: callers defer this specifically to contain a
// panic to the one goroutine (e.g. a single client session) without taking
// down the whole embedding application.
func RecoverPanic(logger zerolog.Logger) {
	if r := recover(); r != nil {
		stack := make([]byte, 1024*8)
		length := runtime.Stack(stack, false)
		logger.Error().Msgf("recovered from panic: %v\nStack trace:\n%s\n", r, stack[:length])
	}
}

// InitLogger points the process-global zerolog logger at a colored console
// writer. It's a convenience for standalone-binary consumers and must only
// be called explicitly from a main()/cmd entrypoint -- never from a
// package init(), which would silently reconfigure global logging state as
// an import side effect for every consumer of that package.
func InitLogger() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		return file + ":" + strconv.Itoa(line)
	}
	log.Logger = log.With().Caller().Logger().Output(zerolog.ConsoleWriter{Out: os.Stdout})
}
