package conformance_test

import (
	"testing"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipcash/conformance"
)

// TestAgainstFakeHub runs the whole suite against nmilat's own fake Hub (T02-05).
func TestAgainstFakeHub(t *testing.T) {
	conformance.Run(t, cashtest.NewFakeHub(t), conformance.Options{})
}
