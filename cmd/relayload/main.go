// Command relayload reproduces production read/write load against a real
// nmilat relay so a change to the scan path can be measured before release.
//
//	relayload gen   -db notes.db -events 5000000      # synthetic store + sample file
//	relayload evict -db notes.db                       # drop the file from page cache
//	relayload serve -db notes.db -addr :7447           # relay + /stats + pprof
//	relayload load  -url ws://relay:7447 -stats http://relay:7448/stats
//
// Run serve in a container with --cpuset-cpus and --memory to reproduce a
// cold cache, and load somewhere unconstrained.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "gen":
		err = runGen(os.Args[2:])
	case "evict":
		err = runEvict(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "load":
		err = runLoad(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "relayload:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: relayload gen|evict|serve|load [flags]")
	os.Exit(2)
}
