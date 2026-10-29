//go:build darwin && cgo

package darwinsdk

/*
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioccom.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)

enum {
	ifaliasreq_size = sizeof(struct ifaliasreq),
	ifaliasreq_name_offset = offsetof(struct ifaliasreq, ifra_name),
	ifaliasreq_name_size = MEMBER_SIZE(struct ifaliasreq, ifra_name),
	ifaliasreq_addr_offset = offsetof(struct ifaliasreq, ifra_addr),
	ifaliasreq_addr_size = MEMBER_SIZE(struct ifaliasreq, ifra_addr),
	ifaliasreq_broadaddr_offset = offsetof(struct ifaliasreq, ifra_broadaddr),
	ifaliasreq_broadaddr_size = MEMBER_SIZE(struct ifaliasreq, ifra_broadaddr),
	ifaliasreq_mask_offset = offsetof(struct ifaliasreq, ifra_mask),
	ifaliasreq_mask_size = MEMBER_SIZE(struct ifaliasreq, ifra_mask),

	in6_aliasreq_size = sizeof(struct in6_aliasreq),
	in6_aliasreq_name_offset = offsetof(struct in6_aliasreq, ifra_name),
	in6_aliasreq_name_size = MEMBER_SIZE(struct in6_aliasreq, ifra_name),
	in6_aliasreq_addr_offset = offsetof(struct in6_aliasreq, ifra_addr),
	in6_aliasreq_addr_size = MEMBER_SIZE(struct in6_aliasreq, ifra_addr),
	in6_aliasreq_dstaddr_offset = offsetof(struct in6_aliasreq, ifra_dstaddr),
	in6_aliasreq_dstaddr_size = MEMBER_SIZE(struct in6_aliasreq, ifra_dstaddr),
	in6_aliasreq_prefixmask_offset = offsetof(struct in6_aliasreq, ifra_prefixmask),
	in6_aliasreq_prefixmask_size = MEMBER_SIZE(struct in6_aliasreq, ifra_prefixmask),
	in6_aliasreq_flags_offset = offsetof(struct in6_aliasreq, ifra_flags),
	in6_aliasreq_flags_size = MEMBER_SIZE(struct in6_aliasreq, ifra_flags),
	in6_aliasreq_lifetime_offset = offsetof(struct in6_aliasreq, ifra_lifetime),
	in6_aliasreq_lifetime_size = MEMBER_SIZE(struct in6_aliasreq, ifra_lifetime),

	in6_addrlifetime_size = sizeof(struct in6_addrlifetime),
	in6_addrlifetime_expire_offset = offsetof(struct in6_addrlifetime, ia6t_expire),
	in6_addrlifetime_expire_size = MEMBER_SIZE(struct in6_addrlifetime, ia6t_expire),
	in6_addrlifetime_preferred_offset = offsetof(struct in6_addrlifetime, ia6t_preferred),
	in6_addrlifetime_preferred_size = MEMBER_SIZE(struct in6_addrlifetime, ia6t_preferred),
	in6_addrlifetime_vltime_offset = offsetof(struct in6_addrlifetime, ia6t_vltime),
	in6_addrlifetime_vltime_size = MEMBER_SIZE(struct in6_addrlifetime, ia6t_vltime),
	in6_addrlifetime_pltime_offset = offsetof(struct in6_addrlifetime, ia6t_pltime),
	in6_addrlifetime_pltime_size = MEMBER_SIZE(struct in6_addrlifetime, ia6t_pltime),
};
*/
import "C"

// Field is one member of a C structure as the C compiler lays it out.
type Field struct {
	Name   string
	Offset uintptr
	Size   uintptr
}

// Struct is a C structure's total size and its members in declaration order.
type Struct struct {
	Name   string
	Size   uintptr
	Fields []Field
}

// IfAliasReq is struct ifaliasreq from <net/if.h>.
var IfAliasReq = Struct{
	Name: "struct ifaliasreq",
	Size: C.ifaliasreq_size,
	Fields: []Field{
		{"ifra_name", C.ifaliasreq_name_offset, C.ifaliasreq_name_size},
		{"ifra_addr", C.ifaliasreq_addr_offset, C.ifaliasreq_addr_size},
		{"ifra_broadaddr", C.ifaliasreq_broadaddr_offset, C.ifaliasreq_broadaddr_size},
		{"ifra_mask", C.ifaliasreq_mask_offset, C.ifaliasreq_mask_size},
	},
}

// In6AliasReq is struct in6_aliasreq from <netinet6/in6_var.h>.
var In6AliasReq = Struct{
	Name: "struct in6_aliasreq",
	Size: C.in6_aliasreq_size,
	Fields: []Field{
		{"ifra_name", C.in6_aliasreq_name_offset, C.in6_aliasreq_name_size},
		{"ifra_addr", C.in6_aliasreq_addr_offset, C.in6_aliasreq_addr_size},
		{"ifra_dstaddr", C.in6_aliasreq_dstaddr_offset, C.in6_aliasreq_dstaddr_size},
		{"ifra_prefixmask", C.in6_aliasreq_prefixmask_offset, C.in6_aliasreq_prefixmask_size},
		{"ifra_flags", C.in6_aliasreq_flags_offset, C.in6_aliasreq_flags_size},
		{"ifra_lifetime", C.in6_aliasreq_lifetime_offset, C.in6_aliasreq_lifetime_size},
	},
}

// In6AddrLifetime is struct in6_addrlifetime from <netinet6/in6_var.h>.
var In6AddrLifetime = Struct{
	Name: "struct in6_addrlifetime",
	Size: C.in6_addrlifetime_size,
	Fields: []Field{
		{"ia6t_expire", C.in6_addrlifetime_expire_offset, C.in6_addrlifetime_expire_size},
		{"ia6t_preferred", C.in6_addrlifetime_preferred_offset, C.in6_addrlifetime_preferred_size},
		{"ia6t_vltime", C.in6_addrlifetime_vltime_offset, C.in6_addrlifetime_vltime_size},
		{"ia6t_pltime", C.in6_addrlifetime_pltime_offset, C.in6_addrlifetime_pltime_size},
	},
}

// Macro values, as the headers expand them.
const (
	IFNAMSIZ              = C.IFNAMSIZ                   // <net/if.h>
	SIOCAIFADDR           = C.SIOCAIFADDR                // <sys/sockio.h>
	SIOCAIFADDR_IN6       = C.SIOCAIFADDR_IN6            // <netinet6/in6_var.h>
	IN6_IFF_NODAD         = C.IN6_IFF_NODAD              // <netinet6/in6_var.h>
	ND6_INFINITE_LIFETIME = C.ND6_INFINITE_LIFETIME      // <netinet6/nd6.h>
	AF_INET               = C.AF_INET                    // <sys/socket.h>
	AF_INET6              = C.AF_INET6                   // <sys/socket.h>
	SizeofSockaddrIn      = C.sizeof_struct_sockaddr_in  // <netinet/in.h>
	SizeofSockaddrIn6     = C.sizeof_struct_sockaddr_in6 // <netinet6/in6.h>
)
