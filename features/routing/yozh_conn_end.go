package routing

// ConnEnd is the end of one dispatch, as the router that routed it sends it on: numbers and the
// class of the outbound's error, never an address.
type ConnEnd struct {
	Conn        uint64
	TsMs        int64 // unix milliseconds of the end
	DurMs       int64
	FirstDownMs int64 // -1: nothing came back
	LastUpMs    int64 // -1: nothing went up
	LastDownMs  int64 // -1: nothing came back
	Up          int64
	Down        int64
	Error       string // "", "refused", "timeout", "udp-not-supported" or "other"
}

// EndReporting is a router that can report the ends of dispatches; ReportsEnd tells whether any of
// its rules asks for that now.
type EndReporting interface {
	ReportsEnd() bool
}

// ConnEndReporter is a route that sends the end of the dispatch it routed through its own rule.
type ConnEndReporter interface {
	ReportEnd(ConnEnd)
}
