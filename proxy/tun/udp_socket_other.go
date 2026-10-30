//go:build !darwin

package tun

// defaultUDPFlowPolicy elsewhere: no socket table is read, so a flow is upstream's full cone —
// keyed by its source, never re-checked, ended only by its outbound.
func defaultUDPFlowPolicy() udpFlowPolicy {
	return udpFlowPolicy{}
}
