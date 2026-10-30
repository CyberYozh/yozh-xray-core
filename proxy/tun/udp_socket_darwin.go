//go:build darwin

package tun

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"golang.org/x/sys/unix"
)

// defaultUDPFlowPolicy on macOS: flows are held to their sockets through the kernel's UDP table
// (udp_flow_policy.go).
func defaultUDPFlowPolicy() udpFlowPolicy {
	return udpFlowPolicy{
		lookup:  &pcblistLookup{read: readUDPPcblist, engine: int32(os.Getpid())},
		window:  2 * time.Millisecond,
		silence: time.Second,
		recheck: 5 * time.Second,
		idle:    udpIdleByFirstPacket,
	}
}

// The record stream of sysctl net.inet.udp.pcblist_n (xnu bsd/netinet/in_pcblist.c,
// get_pcblist_n): an xinpgen, then per socket a run of records that each begin with
// u_int32_t len, kind and are padded to 8 bytes — xinpcb_n, xsocket_n, two xsockbuf_n,
// xsockstat_n — then a trailing xinpgen. User-space (Skywalk) flows follow in the same shape
// (bsd/net/ntstat.c, nstat_userland_list_snapshot), with generation 0 and their pid in xsocket_n.
// The structs are pack(4); the offsets are from bsd/netinet/in_pcb.h and bsd/sys/socketvar.h:
//
//	xinpcb_n:  +16 inp_fport, +18 inp_lport (big-endian) +28 inp_gencnt +44 inp_vflag
//	           +48 inp_dependfaddr[16] +64 inp_dependladdr[16]
//	xsocket_n: +68 so_last_pid +72 so_e_pid
//
// The walk goes by (len, kind) and never by a fixed stride; a record shorter than the fields read,
// or a length that runs past the buffer, makes the whole read unusable (unknown), never a guess.
// The offsets themselves are constants: a macOS that moves one of these fields would still hand over
// records of the right length and kind, so before its first answer the lookup proves them on the
// kernel it runs on (selfCheck).
const (
	pcbKindSocket   = 0x001 // XSO_SOCKET
	pcbKindInpcb    = 0x010 // XSO_INPCB
	pcbXinpgenLen   = 24
	pcbInpcbMinLen  = 80
	pcbSocketMinLen = 76
	pcbOffFport     = 16
	pcbOffLport     = 18
	pcbOffGencnt    = 28
	pcbOffVflag     = 44
	pcbOffFaddr     = 48
	pcbOffLaddr     = 64
	pcbOffLastPID   = 68
	pcbOffEffPID    = 72
	inpIPv4         = 0x1
	inpIPv6         = 0x2
)

type pcbEntry struct {
	port   uint16
	vflag  uint8
	laddr  netip.Addr // IPv4 for an IPv4 socket and for an IPv4-mapped one; unspecified = wildcard
	fport  uint16     // the peer, for a connected socket or a user-space flow; 0 and unspecified: none
	faddr  netip.Addr // read as laddr is
	gencnt uint64
	pid    int32
}

// holds: this socket could be the one sending from source (on the entry's own port) — bound to
// exactly that address, or to a wildcard of its family. A dual-stack IPv6 socket carries both
// flags (measured: vflag 0x3 for Go's "udp" on [::], 0x2 for "udp6", 0x1 for "udp4").
func (e pcbEntry) holds(source netip.Addr) bool {
	if e.laddr.IsUnspecified() {
		if source.Is4() {
			return e.vflag&inpIPv4 != 0
		}
		return e.vflag&inpIPv6 != 0
	}
	return e.laddr == source
}

func (e pcbEntry) mark() socketMark {
	if e.gencnt != 0 {
		return socketMark{generation: e.gencnt}
	}
	return socketMark{pid: e.pid, fport: e.fport, faddr: e.faddr}
}

// pcblistLookup reads the kernel's UDP table. Before its first answer it checks its own parser
// (selfCheck); a parser that fails answers "unknown" for as long as the lookup lives — the flows then
// keep upstream's full cone, and the log says so once — instead of answering with the fields of
// another layout.
//
// The engine's own sockets are never a program's (identityOf): `engine` is its process, this one in
// the product; 0 sets nothing aside.
type pcblistLookup struct {
	read   func() ([]byte, error)
	engine int32

	check     sync.Once
	untrusted bool // the parser failed its check
}

var pcblistUnreadable sync.Once

func (l *pcblistLookup) identify(sources []net.Destination) []socketIdentity {
	identities := make([]socketIdentity, len(sources))
	l.check.Do(func() {
		if err := l.selfCheck(); err != nil {
			l.untrusted = true
			errors.LogWarningInner(context.Background(), err, "[tun] the UDP socket table does not read as this engine expects: UDP flows are not re-checked against their sockets in this session")
		}
	})
	if l.untrusted {
		return identities // unknown: flows keep upstream's full cone
	}
	byPort, err := l.table()
	if err != nil {
		pcblistUnreadable.Do(func() {
			errors.LogWarningInner(context.Background(), err, "[tun] the UDP socket table cannot be read: UDP flows are not re-checked against their sockets")
		})
		return identities // unknown: flows keep upstream's full cone
	}
	for i, source := range sources {
		identities[i] = identityOf(byPort, source, l.engine)
	}
	return identities
}

// selfCheck proves the parser on this kernel with two UDP sockets of its own on loopback, the first
// connected to the second. Each must be read once on its own port, with this process's pid and its
// own peer (the second's port and address for the first, none for the second); the two must have
// generations of their own; a second read must give the same generations; closed, they must be gone.
// What each step catches in a field read from the wrong place: a port finds no socket anywhere,
// which is upstream's full cone again (a program handed a reused port rides the previous program's
// flow and route); a generation that changes between reads ends every flow at every check; one that
// all sockets share (zero included) takes a new socket for the old one; a pid or a peer mismarks
// Skywalk flows; and a table that never changes keeps a closed socket in it.
func (l *pcblistLookup) selfCheck() error {
	loopback := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	var ports [2]uint16
	var sockets [2]*net.UDPConn
	defer func() {
		for _, socket := range sockets {
			if socket != nil {
				socket.Close()
			}
		}
	}()
	for _, i := range []int{1, 0} {
		var socket *net.UDPConn
		var err error
		if i == 1 {
			socket, err = net.ListenUDP("udp4", &net.UDPAddr{IP: loopback.AsSlice()})
		} else {
			socket, err = net.DialUDP("udp4", &net.UDPAddr{IP: loopback.AsSlice()}, &net.UDPAddr{IP: loopback.AsSlice(), Port: int(ports[1])})
		}
		if err != nil {
			return errors.New("pcblist_n self-check: no loopback socket of its own").Base(err)
		}
		sockets[i] = socket
		ports[i] = uint16(socket.LocalAddr().(*net.UDPAddr).Port)
	}
	peers := [2]pcbEntry{{fport: ports[1], faddr: loopback}, {faddr: netip.IPv4Unspecified()}}
	own := int32(os.Getpid())
	generations := func() (found [2]uint64, err error) {
		byPort, err := l.table()
		if err != nil {
			return found, err
		}
		for i, port := range ports {
			var entries []pcbEntry
			for _, entry := range byPort[port] {
				if entry.holds(loopback) {
					entries = append(entries, entry)
				}
			}
			if len(entries) != 1 || entries[0].pid != own {
				return found, errors.New("pcblist_n self-check: a socket of its own is not read as itself")
			}
			if entries[0].fport != peers[i].fport || entries[0].faddr != peers[i].faddr {
				return found, errors.New("pcblist_n self-check: a socket of its own is not read with its own peer")
			}
			found[i] = entries[0].gencnt
		}
		return found, nil
	}
	first, err := generations()
	if err != nil {
		return err
	}
	if first[0] == first[1] {
		return errors.New("pcblist_n self-check: two sockets of its own are read as one")
	}
	again, err := generations()
	if err != nil {
		return err
	}
	if again != first {
		return errors.New("pcblist_n self-check: a socket of its own is read as another one on the next read")
	}
	for i := range sockets {
		sockets[i].Close()
		sockets[i] = nil
	}
	byPort, err := l.table()
	if err != nil {
		return err
	}
	for i, port := range ports {
		for _, entry := range byPort[port] {
			if entry.gencnt == first[i] {
				return errors.New("pcblist_n self-check: a socket of its own is still read after it closed")
			}
		}
	}
	return nil
}

func (l *pcblistLookup) table() (map[uint16][]pcbEntry, error) {
	raw, err := l.read()
	if err != nil {
		return nil, err
	}
	return parsePcblist(raw)
}

// identityOf: the sockets that could be sending from source, save those of the engine's own process
// (`engine`; 0: none). The kernel picks the port of a dual-stack socket — Go's "udp" on the wildcard,
// what an outbound opens for a UDP flow — without looking at IPv4 sockets, so an outbound socket of
// the engine can be given the port a program holds on 0.0.0.0 or on an address of its own. Counted,
// it is a second socket there: the port reads as changed hands, and the program's flows end while it
// keeps its socket. The engine's own traffic never comes in through the tun, so its sockets are set
// aside; a socket of any other process on the port still counts. The owner is read as a mark reads it: the
// effective pid when the socket has one, else the last pid.
func identityOf(byPort map[uint16][]pcbEntry, source net.Destination, engine int32) socketIdentity {
	if source.Address == nil || !source.Address.Family().IsIP() {
		return socketIdentity{}
	}
	addr, ok := netip.AddrFromSlice(source.Address.IP())
	if !ok {
		return socketIdentity{}
	}
	addr = addr.Unmap()
	identity := socketIdentity{known: true}
	for _, entry := range byPort[uint16(source.Port)] {
		if engine != 0 && entry.pid == engine {
			continue
		}
		if entry.holds(addr) {
			identity.marks = append(identity.marks, entry.mark())
		}
	}
	slices.SortFunc(identity.marks, compareSocketMarks)
	identity.marks = slices.Compact(identity.marks)
	return identity
}

// readUDPPcblist reads the table; ENOMEM means it grew between sizing and reading, so it is read again.
func readUDPPcblist() ([]byte, error) {
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		var raw []byte
		if raw, err = unix.SysctlRaw("net.inet.udp.pcblist_n"); err == nil {
			return raw, nil
		}
		if err != unix.ENOMEM {
			return nil, err
		}
	}
	return nil, err
}

func pcbRoundUp8(n int) int {
	if n <= 0 {
		return 8
	}
	return 1 + ((n - 1) | 7)
}

func parsePcblist(raw []byte) (map[uint16][]pcbEntry, error) {
	if len(raw) < pcbXinpgenLen {
		return nil, errors.New("pcblist_n: shorter than its header")
	}
	header := int(binary.LittleEndian.Uint32(raw))
	if header < pcbXinpgenLen || header > len(raw) {
		return nil, errors.New("pcblist_n: bad header length")
	}
	byPort := map[uint16][]pcbEntry{}
	add := func(inpcb, socket int) {
		if entry, ok := pcbEntryAt(raw, inpcb, socket); ok {
			byPort[entry.port] = append(byPort[entry.port], entry)
		}
	}
	pending := -1 // an xinpcb_n whose xsocket_n has not come yet
	for offset := pcbRoundUp8(header); offset < len(raw); {
		rest := len(raw) - offset
		if rest == pcbXinpgenLen {
			break // the trailing xinpgen
		}
		if rest < 8 {
			return nil, errors.New("pcblist_n: truncated record")
		}
		length := int(binary.LittleEndian.Uint32(raw[offset:]))
		kind := binary.LittleEndian.Uint32(raw[offset+4:])
		if length < 8 || length > rest {
			return nil, errors.New("pcblist_n: bad record length")
		}
		switch kind {
		case pcbKindInpcb:
			if length < pcbInpcbMinLen {
				return nil, errors.New("pcblist_n: short xinpcb_n")
			}
			if pending >= 0 {
				add(pending, -1)
			}
			pending = offset
		case pcbKindSocket:
			if length < pcbSocketMinLen {
				return nil, errors.New("pcblist_n: short xsocket_n")
			}
			if pending >= 0 {
				add(pending, offset)
				pending = -1
			}
		}
		offset += pcbRoundUp8(length)
	}
	if pending >= 0 {
		add(pending, -1)
	}
	return byPort, nil
}

// pcbAddrAt reads one of a pcb's two addresses (in_addr_4in6 / in6_addr, 16 bytes).
func pcbAddrAt(field []byte, vflag uint8) netip.Addr {
	var address [16]byte
	copy(address[:], field)
	addr := netip.AddrFrom16(address)
	switch {
	// An IPv4 socket keeps its address in the last four bytes (in_addr_4in6). An IPv6 socket keeps
	// an IPv6 address — xnu turns a socket bound or connected to an IPv4-mapped address into an
	// IPv4 one — so only the mapped form is folded there; ::1 stays ::1, and :: is the wildcard.
	case vflag&inpIPv6 == 0 || addr.Is4In6():
		return netip.AddrFrom4([4]byte(address[12:16]))
	// xnu keeps a link-local address's scope inside it (KAME, bytes 2-3: fe80::1%lo0 reads as
	// fe80:1::1, measured); a packet's source carries none, so the scope is cleared.
	case addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast():
		address[2], address[3] = 0, 0
		return netip.AddrFrom16(address)
	}
	return addr
}

func pcbEntryAt(raw []byte, inpcb, socket int) (pcbEntry, bool) {
	vflag := raw[inpcb+pcbOffVflag]
	if vflag&(inpIPv4|inpIPv6) == 0 {
		return pcbEntry{}, false
	}
	entry := pcbEntry{
		port:   binary.BigEndian.Uint16(raw[inpcb+pcbOffLport:]),
		vflag:  vflag,
		laddr:  pcbAddrAt(raw[inpcb+pcbOffLaddr:inpcb+pcbOffLaddr+16], vflag),
		fport:  binary.BigEndian.Uint16(raw[inpcb+pcbOffFport:]),
		faddr:  pcbAddrAt(raw[inpcb+pcbOffFaddr:inpcb+pcbOffFaddr+16], vflag),
		gencnt: binary.LittleEndian.Uint64(raw[inpcb+pcbOffGencnt:]),
	}
	if socket >= 0 {
		entry.pid = int32(binary.LittleEndian.Uint32(raw[socket+pcbOffEffPID:]))
		if entry.pid == 0 {
			entry.pid = int32(binary.LittleEndian.Uint32(raw[socket+pcbOffLastPID:]))
		}
	}
	return entry, true
}
