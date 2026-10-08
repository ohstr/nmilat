package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/relay"
)

// stats is what /stats reports; load samples it once a second.
type stats struct {
	Goroutines  int     `json:"goroutines"`
	ScanWaiting int     `json:"scan_waiting"`
	ScanHolding int     `json:"scan_holding"`
	MajFlt      int64   `json:"majflt"`
	MinFlt      int64   `json:"minflt"`
	ReadBytes   int64   `json:"read_bytes"`
	CPUSeconds  float64 `json:"cpu_seconds"`
	MemCurrent  int64   `json:"cgroup_mem_current"`
	IOPressure  string  `json:"cgroup_io_pressure"`
}

func collectStats() stats {
	var s stats
	s.Goroutines = runtime.NumGoroutine()

	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	for _, g := range bytes.Split(buf, []byte("\n\n")) {
		if !bytes.Contains(g, []byte("relay.(*EventStore).viewScan(")) {
			continue
		}
		if bytes.Contains(g, []byte("bbolt.(*DB).View(")) {
			s.ScanHolding++
		} else {
			s.ScanWaiting++
		}
	}

	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) == nil {
		s.MajFlt, s.MinFlt = ru.Majflt, ru.Minflt
		s.CPUSeconds = float64(ru.Utime.Sec+ru.Stime.Sec) + float64(ru.Utime.Usec+ru.Stime.Usec)/1e6
	}
	if b, err := os.ReadFile("/proc/self/io"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "read_bytes: "); ok {
				s.ReadBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	if b, err := os.ReadFile("/sys/fs/cgroup/memory.current"); err == nil {
		s.MemCurrent, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
	if b, err := os.ReadFile("/sys/fs/cgroup/io.pressure"); err == nil {
		s.IOPressure = strings.SplitN(string(b), "\n", 2)[0]
	}
	return s
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	db := fs.String("db", "notes.db", "store path")
	addr := fs.String("addr", ":7447", "relay listen address")
	statsAddr := fs.String("stats", ":7448", "stats + pprof listen address")
	_ = fs.Parse(args)

	// relay.ohstr.com's limitation block.
	meta := &nip11.Metadata{
		Name: "relayload",
		Limitation: nip11.Limitation{
			MaxLimit:         500,
			MaxSubscriptions: 20,
			MaxMessageLength: 262144,
		},
	}
	// Same construction as ncli relay: default store options.
	store, err := relay.NewEventStore(*db, &meta.Limitation)
	if err != nil {
		return err
	}
	defer store.Close()
	handler := relay.NewSessionHandler(store, meta, nil)

	http.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(collectStats())
	})
	go func() {
		// DefaultServeMux carries /stats and /debug/pprof.
		if err := http.ListenAndServe(*statsAddr, nil); err != nil {
			fmt.Fprintln(os.Stderr, "stats:", err)
		}
	}()
	fmt.Printf("serving %s on %s (stats %s), GOMAXPROCS=%d NumCPU=%d\n",
		*db, *addr, *statsAddr, runtime.GOMAXPROCS(0), runtime.NumCPU())
	return http.ListenAndServe(*addr, handler)
}
