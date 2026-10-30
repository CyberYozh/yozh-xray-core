package dispatcher

import "syscall"

// WSAECONNREFUSED and WSAETIMEDOUT. syscall's ECONNREFUSED and ETIMEDOUT are numbers Go made up on
// Windows, and Errno(10060).Timeout() is false there.
const (
	refusedErrno  = syscall.Errno(10061)
	timedOutErrno = syscall.Errno(10060)
)
