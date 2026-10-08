//go:build !linux

package main

import "errors"

func runEvict([]string) error {
	return errors.New("evict needs linux (posix_fadvise)")
}
