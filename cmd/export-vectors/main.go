// Command export-vectors writes the cross-implementation test vector files
// that package vectors builds.
//
//	go run ./cmd/export-vectors -out testdata/vectors
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ohstr/nmilat/vectors"
)

func main() {
	out := flag.String("out", "testdata/vectors", "directory to write the vector files into")
	flag.Parse()
	if err := vectors.WriteAll(*out); err != nil {
		fmt.Fprintln(os.Stderr, "export-vectors:", err)
		os.Exit(1)
	}
}
