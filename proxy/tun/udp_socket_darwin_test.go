//go:build darwin

package tun

// The socket lookup against the real kernel table: loopback sockets of this test process, no root.

import (
	"encoding/binary"
	gonet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

func listenUDP(t *testing.T, network, address string) *gonet.UDPConn {
	t.Helper()
	pc, err := gonet.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	return pc.(*gonet.UDPConn)
}

func portOf(c *gonet.UDPConn) net.Port { return net.Port(c.LocalAddr().(*gonet.UDPAddr).Port) }

func identityNow(t *testing.T, source net.Destination) socketIdentity {
	t.Helper()
	identity := (&pcblistLookup{read: readUDPPcblist}).identify([]net.Destination{source})[0]
	if !identity.known {
		t.Fatal("the UDP table could not be read")
	}
	return identity
}

// The property the lookup rests on, measured with its own parser: the old socket and the new one
// on the same port are told apart, and a closed socket is gone.
func TestUDPFlowTheTableTellsAnOldSocketFromANewOneOnTheSamePort(t *testing.T) {
	for i := 0; i < 50; i++ {
		old := listenUDP(t, "udp4", "127.0.0.1:0")
		source := net.UDPDestination(net.ParseAddress("127.0.0.1"), portOf(old))
		before := identityNow(t, source)
		old.Close()
		gone := identityNow(t, source)
		replacement := listenUDP(t, "udp4", source.NetAddr())
		after := identityNow(t, source)
		replacement.Close()

		if len(before.marks) != 1 || len(after.marks) != 1 {
			t.Fatalf("port %d: marks before %v, after %v — want one socket each", source.Port, before.marks, after.marks)
		}
		if len(gone.marks) != 0 {
			t.Fatalf("port %d: a closed socket is still in the table: %v", source.Port, gone.marks)
		}
		if before.same(after) {
			t.Fatalf("port %d: the new socket looks like the old one (%v)", source.Port, before.marks)
		}
	}
}

// Matched by port AND address: a socket on the same port number bound elsewhere, or of the other
// family, is not the flow's socket; a wildcard of the flow's family is.
func TestUDPFlowTheTableMatchesTheSourceAddressAndFamily(t *testing.T) {
	loopback := listenUDP(t, "udp4", "127.0.0.1:0")
	defer loopback.Close()
	port := portOf(loopback)
	onLoopback := net.UDPDestination(net.ParseAddress("127.0.0.1"), port)
	onUtun := net.UDPDestination(net.ParseAddress("198.18.0.2"), port)
	if got := identityNow(t, onLoopback).marks; len(got) != 1 {
		t.Fatalf("the socket on 127.0.0.1:%d not found: %v", port, got)
	}
	if got := identityNow(t, onUtun).marks; len(got) != 0 {
		t.Fatalf("a socket on 127.0.0.1 taken for the utun source 198.18.0.2: %v", got)
	}

	wildcard := listenUDP(t, "udp4", "0.0.0.0:0")
	defer wildcard.Close()
	onUtun = net.UDPDestination(net.ParseAddress("198.18.0.2"), portOf(wildcard))
	if got := identityNow(t, onUtun).marks; len(got) != 1 {
		t.Fatalf("a wildcard IPv4 socket must answer for the utun source: %v", got)
	}

	dual := listenUDP(t, "udp", ":0") // [::] without V6ONLY: sends IPv4 too
	defer dual.Close()
	onUtun = net.UDPDestination(net.ParseAddress("198.18.0.2"), portOf(dual))
	if got := identityNow(t, onUtun).marks; len(got) != 1 {
		t.Fatalf("a dual-stack wildcard socket must answer for an IPv4 source: %v", got)
	}

	v6only := listenUDP(t, "udp6", "[::]:0")
	defer v6only.Close()
	onUtun = net.UDPDestination(net.ParseAddress("198.18.0.2"), portOf(v6only))
	if got := identityNow(t, onUtun).marks; len(got) != 0 {
		t.Fatalf("a V6ONLY socket answered for an IPv4 source: %v", got)
	}
	v6 := net.UDPDestination(net.ParseAddress("fd00::2"), portOf(v6only))
	if got := identityNow(t, v6).marks; len(got) != 1 {
		t.Fatalf("a V6ONLY wildcard socket must answer for an IPv6 source: %v", got)
	}

	v6loopback := listenUDP(t, "udp6", "[::1]:0")
	defer v6loopback.Close()
	if got := identityNow(t, net.UDPDestination(net.ParseAddress("::1"), portOf(v6loopback))).marks; len(got) != 1 {
		t.Fatalf("::1 must stay ::1, not be read as an IPv4 address: %v", got)
	}
	if got := identityNow(t, net.UDPDestination(net.ParseAddress("0.0.0.1"), portOf(v6loopback))).marks; len(got) != 0 {
		t.Fatalf("::1 was read as 0.0.0.1: %v", got)
	}

	linkLocal := listenUDP(t, "udp6", "[fe80::1%lo0]:0") // the kernel keeps its scope inside the address
	defer linkLocal.Close()
	if got := identityNow(t, net.UDPDestination(net.ParseAddress("fe80::1"), portOf(linkLocal))).marks; len(got) != 1 {
		t.Fatalf("a socket on fe80::1%%lo0 must answer for the source fe80::1: %v", got)
	}
}

// ---- The parser on records the test writes -------------------------------------------------------

// record: one pcb as get_pcblist_n writes it — xinpcb_n (104 bytes) then xsocket_n (104 bytes).
func pcbRecord(port uint16, vflag uint8, local [16]byte, gencnt uint64, lastPID, effectivePID uint32) []byte {
	return pcbRecordTo(port, vflag, local, 0, [16]byte{}, gencnt, lastPID, effectivePID)
}

// pcbRecordTo: the same, with a peer (a connected socket, or a user-space flow's remote end).
func pcbRecordTo(port uint16, vflag uint8, local [16]byte, foreignPort uint16, foreign [16]byte, gencnt uint64, lastPID, effectivePID uint32) []byte {
	inpcb := make([]byte, 104)
	binary.LittleEndian.PutUint32(inpcb[0:], 104)
	binary.LittleEndian.PutUint32(inpcb[4:], pcbKindInpcb)
	binary.BigEndian.PutUint16(inpcb[pcbOffFport:], foreignPort)
	binary.BigEndian.PutUint16(inpcb[pcbOffLport:], port)
	binary.LittleEndian.PutUint64(inpcb[pcbOffGencnt:], gencnt)
	inpcb[pcbOffVflag] = vflag
	copy(inpcb[pcbOffFaddr:], foreign[:])
	copy(inpcb[pcbOffLaddr:], local[:])
	socket := make([]byte, 104)
	binary.LittleEndian.PutUint32(socket[0:], 104)
	binary.LittleEndian.PutUint32(socket[4:], pcbKindSocket)
	binary.LittleEndian.PutUint32(socket[pcbOffLastPID:], lastPID)
	binary.LittleEndian.PutUint32(socket[pcbOffEffPID:], effectivePID)
	return append(inpcb, socket...)
}

func pcbTable(count uint32, records ...[]byte) []byte {
	xinpgen := func() []byte {
		b := make([]byte, pcbXinpgenLen)
		binary.LittleEndian.PutUint32(b[0:], pcbXinpgenLen)
		binary.LittleEndian.PutUint32(b[4:], count) // xig_count: may happen to equal a record kind
		return b
	}
	table := xinpgen() // 24 bytes: the first record starts right after it
	for _, r := range records {
		table = append(table, r...)
	}
	return append(table, xinpgen()...)
}

func v4local(a, b, c, d byte) (l [16]byte) {
	l[12], l[13], l[14], l[15] = a, b, c, d
	return l
}

func TestUDPFlowTheTableParserReadsRecordsAndRefusesBrokenOnes(t *testing.T) {
	// Sixteen pcbs: the trailing xinpgen's count is 0x10, XSO_INPCB — it must not be read as one.
	var records [][]byte
	for i := 0; i < 16; i++ {
		records = append(records, pcbRecord(uint16(40000+i), inpIPv4, v4local(198, 18, 0, 2), uint64(1000+i), 77, 0))
	}
	// A user-space (Skywalk) flow: generation 0, told apart by its pid.
	records = append(records, pcbRecord(41000, inpIPv4, v4local(0, 0, 0, 0), 0, 55, 66))
	byPort, err := parsePcblist(pcbTable(17, records...))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(byPort); got != 17 {
		t.Fatalf("%d ports parsed, want 17", got)
	}
	if e := byPort[40003][0]; e.gencnt != 1003 || e.laddr.String() != "198.18.0.2" || e.pid != 77 {
		t.Fatalf("pcb on 40003 read as %+v", e)
	}
	skywalk := identityOf(byPort, net.UDPDestination(net.ParseAddress("198.18.0.2"), 41000))
	if len(skywalk.marks) != 1 || skywalk.marks[0].generation != 0 || skywalk.marks[0].pid != 66 {
		t.Fatalf("a generation-0 flow must be marked by its effective pid: %v", skywalk.marks)
	}
	table := pcbTable(16, records[:16]...)
	if _, err := parsePcblist(table); err != nil {
		t.Fatalf("a table of exactly sixteen: %v", err)
	}

	for name, broken := range map[string][]byte{
		"empty":             {},
		"header only, torn": table[:20],
		"record cut short":  table[:pcbRoundUp8(pcbXinpgenLen)+60],
		"length past the end": func() []byte {
			b := append([]byte(nil), table...)
			binary.LittleEndian.PutUint32(b[pcbRoundUp8(pcbXinpgenLen):], 1<<20)
			return b
		}(),
		"xinpcb_n too short": func() []byte {
			b := append([]byte(nil), table...)
			binary.LittleEndian.PutUint32(b[pcbRoundUp8(pcbXinpgenLen):], 40)
			return b
		}(),
	} {
		if _, err := parsePcblist(broken); err == nil {
			t.Errorf("%s: parsed without an error", name)
		}
	}
}

// A user-space (Skywalk) flow has no generation of its own (0): its pid alone would take every flow
// of one process on a port for one socket — a new flow to another peer on a port its predecessor
// had would ride the predecessor's flow and route. So its peer, the foreign port and address, is
// part of its mark. An unconnected one has no peer and stays one flow; an IPv4 peer is read from
// the address's last four bytes only, as the local address is.
func TestUDPFlowAUserSpaceFlowIsMarkedByItsPeerToo(t *testing.T) {
	utun := v4local(198, 18, 0, 2)
	source := net.UDPDestination(net.ParseAddress("198.18.0.2"), 41000)
	identity := func(records ...[]byte) socketIdentity {
		t.Helper()
		byPort, err := parsePcblist(pcbTable(uint32(len(records)), records...))
		if err != nil {
			t.Fatal(err)
		}
		return identityOf(byPort, source)
	}
	toPeer1 := identity(pcbRecordTo(41000, inpIPv4, utun, 443, v4local(192, 0, 2, 1), 0, 55, 66))
	toPeer2 := identity(pcbRecordTo(41000, inpIPv4, utun, 443, v4local(192, 0, 2, 2), 0, 55, 66))
	toPort2 := identity(pcbRecordTo(41000, inpIPv4, utun, 8443, v4local(192, 0, 2, 1), 0, 55, 66))
	if toPeer1.same(toPeer2) || toPeer1.same(toPort2) {
		t.Fatalf("two flows of one pid to two peers read as one socket: %v, %v, %v", toPeer1.marks, toPeer2.marks, toPort2.marks)
	}
	if again := identity(pcbRecordTo(41000, inpIPv4, utun, 443, v4local(192, 0, 2, 1), 0, 55, 66)); !toPeer1.same(again) {
		t.Fatalf("one flow read twice is two: %v, %v", toPeer1.marks, again.marks)
	}
	padded := v4local(192, 0, 2, 1)
	padded[0], padded[5] = 0xAA, 0x55 // in_addr_4in6's padding, whatever is in it
	if withPadding := identity(pcbRecordTo(41000, inpIPv4, utun, 443, padded, 0, 55, 66)); !toPeer1.same(withPadding) {
		t.Fatalf("an IPv4 peer read with its padding: %v, %v", toPeer1.marks, withPadding.marks)
	}
	unconnected := identity(pcbRecord(41000, inpIPv4, utun, 0, 55, 66))
	if again := identity(pcbRecord(41000, inpIPv4, utun, 0, 55, 66)); !unconnected.same(again) || len(unconnected.marks) != 1 {
		t.Fatalf("an unconnected user-space flow must stay one: %v, %v", unconnected.marks, again.marks)
	}
	// A kernel socket is its generation, peer or none: connect() on it is the same socket.
	kernel := identity(pcbRecord(41000, inpIPv4, utun, 1234, 77, 0))
	if connected := identity(pcbRecordTo(41000, inpIPv4, utun, 443, v4local(192, 0, 2, 1), 1234, 77, 0)); !kernel.same(connected) {
		t.Fatalf("a kernel socket that connected read as another: %v, %v", kernel.marks, connected.marks)
	}
}

// The parser reads a connected socket's peer on the real table: the foreign port and address of a
// socket of this test's own, connected to another on loopback.
func TestUDPFlowTheTableReadsAConnectedSocketsPeer(t *testing.T) {
	peer := listenUDP(t, "udp4", "127.0.0.1:0")
	defer peer.Close()
	connected, err := gonet.DialUDP("udp4", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)}, peer.LocalAddr().(*gonet.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()
	raw, err := readUDPPcblist()
	if err != nil {
		t.Fatal(err)
	}
	byPort, err := parsePcblist(raw)
	if err != nil {
		t.Fatal(err)
	}
	entries := byPort[uint16(portOf(connected))]
	if len(entries) != 1 {
		t.Fatalf("%d entries on the connected socket's port", len(entries))
	}
	if e := entries[0]; e.fport != uint16(portOf(peer)) || e.faddr.String() != "127.0.0.1" {
		t.Fatalf("the peer read as %v:%d, want 127.0.0.1:%d", e.faddr, e.fport, portOf(peer))
	}
	if e := byPort[uint16(portOf(peer))][0]; e.fport != 0 || !e.faddr.IsUnspecified() {
		t.Fatalf("an unconnected socket read with a peer %v:%d", e.faddr, e.fport)
	}
}

// A lookup whose table cannot be read answers "unknown" for everyone, and unknown is the same as
// anything: the flow table then keeps upstream's full cone. A read that fails after the
// parser has checked itself is that batch's alone: the next good read answers again.
func TestUDPFlowAnUnreadableKernelTableIsUnknown(t *testing.T) {
	lookup := &pcblistLookup{read: func() ([]byte, error) { return []byte{1, 2, 3}, nil }}
	identity := lookup.identify([]net.Destination{net.UDPDestination(net.ParseAddress("198.18.0.2"), 1)})[0]
	if identity.known || !identity.same(socketIdentity{known: true, marks: []socketMark{{generation: 9}}}) {
		t.Fatalf("an unreadable table gave %+v", identity)
	}

	live := listenUDP(t, "udp4", "127.0.0.1:0")
	defer live.Close()
	sources := []net.Destination{net.UDPDestination(net.ParseAddress("127.0.0.1"), portOf(live))}
	broken := false
	lookup = &pcblistLookup{read: func() ([]byte, error) {
		if broken {
			return []byte{1, 2, 3}, nil
		}
		return readUDPPcblist()
	}}
	if got := lookup.identify(sources)[0]; !got.known || len(got.marks) != 1 {
		t.Fatalf("a live socket on the real table: %+v", got)
	}
	broken = true
	if got := lookup.identify(sources)[0]; got.known {
		t.Fatalf("an unreadable table gave %+v", got)
	}
	broken = false
	if got := lookup.identify(sources)[0]; !got.known || len(got.marks) != 1 {
		t.Fatalf("the table readable again: %+v", got)
	}
}

// ---- The parser checks itself against the kernel it runs on ----------------------------------------

// kernelTableEdited reads the kernel's UDP table and hands every record of kind to edit: the table as
// a macOS that lays those records out otherwise would hand it over, to a parser that reads fixed offsets.
func kernelTableEdited(kind uint32, edit func(record []byte)) func() ([]byte, error) {
	return func() ([]byte, error) {
		raw, err := readUDPPcblist()
		if err != nil {
			return nil, err
		}
		for offset := pcbRoundUp8(int(binary.LittleEndian.Uint32(raw))); len(raw)-offset > pcbXinpgenLen; {
			length := int(binary.LittleEndian.Uint32(raw[offset:]))
			if length < 8 || length > len(raw)-offset {
				break
			}
			if binary.LittleEndian.Uint32(raw[offset+4:]) == kind {
				edit(raw[offset : offset+length])
			}
			offset += pcbRoundUp8(length)
		}
		return raw, nil
	}
}

// Every field the parser reads, read from the wrong place, fails in silence without a check: a port
// read wrong finds no socket anywhere, and a reused port joins the old flow again; a
// generation read from a field that changes ends every flow at every check; one read from a field
// all sockets share takes a new socket for the old one. Before its first answer the parser finds
// sockets of its own in the table, and a parser that does not answers "unknown" — the plain full
// cone, said once in the log — instead of answering with the fields of another layout.
func TestUDPFlowAParserThatDoesNotFindItsOwnSocketsIsNotTrusted(t *testing.T) {
	live := listenUDP(t, "udp4", "127.0.0.1:0")
	defer live.Close()
	sources := []net.Destination{net.UDPDestination(net.ParseAddress("127.0.0.1"), portOf(live))}

	generationPlus := uint64(0)
	changingGeneration := kernelTableEdited(pcbKindInpcb, func(r []byte) {
		binary.LittleEndian.PutUint64(r[pcbOffGencnt:], binary.LittleEndian.Uint64(r[pcbOffGencnt:])+generationPlus)
	})
	var frozen []byte
	for name, read := range map[string]func() ([]byte, error){
		"the port is elsewhere": kernelTableEdited(pcbKindInpcb, func(r []byte) {
			binary.BigEndian.PutUint16(r[pcbOffLport:], 0)
		}),
		"the generation changes on every read": func() ([]byte, error) {
			generationPlus++
			return changingGeneration()
		},
		"every socket has the same generation": kernelTableEdited(pcbKindInpcb, func(r []byte) {
			binary.LittleEndian.PutUint64(r[pcbOffGencnt:], 7)
		}),
		"the pid is elsewhere": kernelTableEdited(pcbKindSocket, func(r []byte) {
			binary.LittleEndian.PutUint32(r[pcbOffLastPID:], 1)
			binary.LittleEndian.PutUint32(r[pcbOffEffPID:], 1)
		}),
		"the foreign port is elsewhere": kernelTableEdited(pcbKindInpcb, func(r []byte) {
			binary.BigEndian.PutUint16(r[pcbOffFport:], 0)
		}),
		"the foreign address is elsewhere": kernelTableEdited(pcbKindInpcb, func(r []byte) {
			clear(r[pcbOffFaddr : pcbOffFaddr+16])
		}),
		"the table stands still": func() ([]byte, error) {
			if frozen == nil {
				raw, err := readUDPPcblist()
				if err != nil {
					return nil, err
				}
				frozen = raw
			}
			return frozen, nil
		},
	} {
		lookup := &pcblistLookup{read: read}
		for answer := 1; answer <= 2; answer++ {
			if got := lookup.identify(sources)[0]; got.known {
				t.Errorf("%s: answer %d is %+v, want unknown", name, answer, got)
			}
		}
	}
}

// Unknown for as long as the lookup lives: a parser that failed its check once is not trusted by
// the next read that happens to look fine.
func TestUDPFlowAParserThatFailedItsCheckIsNotTrustedForTheSession(t *testing.T) {
	live := listenUDP(t, "udp4", "127.0.0.1:0")
	defer live.Close()
	sources := []net.Destination{net.UDPDestination(net.ParseAddress("127.0.0.1"), portOf(live))}
	portless := kernelTableEdited(pcbKindInpcb, func(r []byte) { binary.BigEndian.PutUint16(r[pcbOffLport:], 0) })
	broken := true
	lookup := &pcblistLookup{read: func() ([]byte, error) {
		if broken {
			return portless()
		}
		return readUDPPcblist()
	}}
	first := lookup.identify(sources)[0]
	broken = false
	second := lookup.identify(sources)[0]
	if first.known || second.known {
		t.Fatalf("answers %+v then %+v, want unknown both times", first, second)
	}
}

// The check costs reads of its own before the first answer, and none after it: every later answer
// is one read of the table, as before.
func TestUDPFlowTheParserChecksItselfOnceBeforeItsFirstAnswer(t *testing.T) {
	live := listenUDP(t, "udp4", "127.0.0.1:0")
	defer live.Close()
	sources := []net.Destination{net.UDPDestination(net.ParseAddress("127.0.0.1"), portOf(live))}
	reads := 0
	lookup := &pcblistLookup{read: func() ([]byte, error) {
		reads++
		return readUDPPcblist()
	}}
	if got := lookup.identify(sources)[0]; !got.known || len(got.marks) != 1 {
		t.Fatalf("first answer: %+v", got)
	}
	if reads < 2 {
		t.Fatalf("the first answer took %d read(s): no check of the parser before it", reads)
	}
	before := reads
	for i := 0; i < 3; i++ {
		if got := lookup.identify(sources)[0]; !got.known || len(got.marks) != 1 {
			t.Fatalf("answer %d: %+v", i+2, got)
		}
	}
	if reads-before != 3 {
		t.Fatalf("three later answers took %d reads, want 3", reads-before)
	}
}

// What macOS runs: the table, a 2 ms window, a 1 s silence, a re-check at least every 5 s of a
// stream, the idle times chosen by the first packet.
func TestUDPFlowDarwinPolicyIsTheSpecs(t *testing.T) {
	policy := defaultUDPFlowPolicy()
	if lookup, ok := policy.lookup.(*pcblistLookup); !ok || lookup.read == nil || policy.window != 2*time.Millisecond || policy.silence != time.Second || policy.recheck != 5*time.Second || policy.idle == nil {
		t.Fatalf("darwin policy: %+v", policy)
	}
}
