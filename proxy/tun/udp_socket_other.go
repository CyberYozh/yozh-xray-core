//go:build !darwin

package tun

// defaultUDPFlowPolicy elsewhere: no socket table is read, so a source is never re-checked and its
// flows are ended only by their outbound. Every destination still takes its own route.
func defaultUDPFlowPolicy() udpFlowPolicy {
	return udpFlowPolicy{}
}
