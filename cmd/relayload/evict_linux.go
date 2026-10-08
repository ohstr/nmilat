package main

import (
	"flag"
	"os"

	"golang.org/x/sys/unix"
)

// runEvict drops the store from the page cache so serve starts cold.
func runEvict(args []string) error {
	fs := flag.NewFlagSet("evict", flag.ExitOnError)
	db := fs.String("db", "notes.db", "store path")
	_ = fs.Parse(args)
	f, err := os.Open(*db)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
}
