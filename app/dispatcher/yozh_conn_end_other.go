//go:build !windows

package dispatcher

import "syscall"

const (
	refusedErrno  = syscall.ECONNREFUSED
	timedOutErrno = syscall.ETIMEDOUT
)
