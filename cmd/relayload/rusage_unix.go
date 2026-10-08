//go:build unix

package main

import "syscall"

func addRusage(s *stats) {
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) == nil {
		s.MajFlt, s.MinFlt = int64(ru.Majflt), int64(ru.Minflt)
		s.CPUSeconds = float64(ru.Utime.Sec+ru.Stime.Sec) + float64(ru.Utime.Usec+ru.Stime.Usec)/1e6
	}
}
