package printweb

import (
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/devapro/passh/internal/i18n"
)

// privateRanges are the only addresses the print page listens on (§7.4).
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),     // RFC 1918
	netip.MustParsePrefix("172.16.0.0/12"),  // RFC 1918
	netip.MustParsePrefix("192.168.0.0/16"), // RFC 1918
	netip.MustParsePrefix("100.64.0.0/10"),  // shared address space (Tailscale)
	netip.MustParsePrefix("fc00::/7"),       // IPv6 unique local addresses
}

var loopbackRanges = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

// allowLoopback lets tests listen on loopback addresses, which are not on
// the private list.
var allowLoopback = false

// interfaceAddrs returns the addresses of a network interface, with their
// subnets. Tests replace it.
var interfaceAddrs = func(name string) ([]netip.Prefix, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, i18n.NewError("no such network interface")
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		ones, bits := n.Mask.Size()
		if ip.Is4() && bits == 128 {
			ones -= 96
		}
		out = append(out, netip.PrefixFrom(ip, ones))
	}
	return out, nil
}

// rangeOf returns the private range that holds a, if any.
func rangeOf(a netip.Addr) (netip.Prefix, bool) {
	ranges := privateRanges
	if allowLoopback {
		ranges = append(slices.Clone(privateRanges), loopbackRanges...)
	}
	for _, p := range ranges {
		if p.Contains(a) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

// checkBindable refuses every address the print page must not listen on:
// the wildcard addresses and anything outside the private ranges.
func checkBindable(a netip.Addr) error {
	a = a.Unmap()
	switch {
	case !a.IsValid():
		return i18n.NewError("no address")
	case a.IsUnspecified():
		return i18n.Errorf("%s: the print page never listens on all addresses (0.0.0.0 or ::)", a)
	case a.Zone() != "":
		return i18n.Errorf("%s: not a private address", a)
	}
	if _, ok := rangeOf(a); !ok {
		return i18n.Errorf("%s is not a private address: the print page listens only on "+
			"10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 and fc00::/7, never on a public address", a)
	}
	return nil
}

// binding is an address the page listens on, with the subnet it allows
// clients from by default.
type binding struct {
	addr   netip.Addr
	subnet netip.Prefix
}

// resolveAddrs finds the addresses to listen on: the private addresses of
// the named interfaces, in order (IPv4 first within an interface, no
// duplicates). Link-local and public addresses are skipped, and said so in
// skipped (messages, shown in the page's language). It fails when no
// private address is left.
func resolveAddrs(interfaces []string) (bound []binding, skipped []i18n.Message, err error) {
	if len(interfaces) == 0 {
		return nil, nil, i18n.NewError("print_web.interfaces is empty: name the interfaces of your LAN or VPN, e.g. [\"eth0\", \"wg0\"]")
	}
	var problems []i18n.Message
	for _, name := range interfaces {
		prefixes, err := interfaceAddrs(name)
		if err != nil {
			problems = append(problems, i18n.Msg("%s: %v", name, err))
			continue
		}
		slices.SortStableFunc(prefixes, func(a, b netip.Prefix) int {
			switch {
			case a.Addr().Is4() == b.Addr().Is4():
				return 0
			case a.Addr().Is4():
				return -1
			}
			return 1
		})
		if len(prefixes) == 0 {
			problems = append(problems, i18n.Msg("%s: no address", name))
		}
		for _, p := range prefixes {
			a := p.Addr().Unmap()
			if a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
				skipped = append(skipped, i18n.Msg("%s: %s is link-local, not used", name, a.WithZone("").String()))
				continue
			}
			if err := checkBindable(a); err != nil {
				skipped = append(skipped, refusal(name, a))
				continue
			}
			if slices.ContainsFunc(bound, func(b binding) bool { return b.addr == a }) {
				continue
			}
			bound = append(bound, binding{addr: a, subnet: defaultSubnet(netip.PrefixFrom(a, p.Bits()))})
		}
	}
	if len(bound) == 0 {
		return nil, skipped, i18n.Errorf("the print page has no private address to listen on (print_web.interfaces): %s",
			messages(append(problems, skipped...)))
	}
	return bound, skipped, nil
}

// refusal says why checkBindable refused the address a of the interface
// name, for the skipped list: only a public address is called public.
func refusal(name string, a netip.Addr) i18n.Message {
	addr := a.String()
	switch {
	case a.IsUnspecified():
		return i18n.Msg("%s: %s is the wildcard address, never used", name, addr)
	case a.IsLoopback():
		return i18n.Msg("%s: %s is a loopback address, not private", name, addr)
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return i18n.Msg("%s: %s is link-local, not used", name, addr)
	case a.IsMulticast():
		return i18n.Msg("%s: %s is a multicast address, not used", name, addr)
	}
	return i18n.Msg("%s: %s is a public address, refused", name, addr)
}

// messages is a list of messages shown in one line, separated by "; ".
type messages []i18n.Message

// String returns the messages in English.
func (ms messages) String() string { return ms.Localize(i18n.Printer{}) }

// Localize implements i18n.Localizer.
func (ms messages) Localize(p i18n.Printer) string {
	texts := make([]string, len(ms))
	for i, m := range ms {
		texts[i] = m.Localize(p)
	}
	return strings.Join(texts, "; ")
}

// defaultSubnet is the subnet clients may come from by default: the
// address's subnet, or for a single-host address (a /32 or /128, as
// Tailscale and some VPNs use) the private range around it.
func defaultSubnet(p netip.Prefix) netip.Prefix {
	if p.Bits() == p.Addr().BitLen() {
		if r, ok := rangeOf(p.Addr()); ok {
			return r
		}
	}
	return p.Masked()
}

// allowedClient reports whether a client address is in one of the
// prefixes.
func allowedClient(a netip.Addr, allowed []netip.Prefix) bool {
	a = a.Unmap().WithZone("")
	return slices.ContainsFunc(allowed, func(p netip.Prefix) bool { return p.Contains(a) })
}

// allowListener closes connections from clients outside allowed before
// anything is read or written, so before TLS.
type allowListener struct {
	net.Listener
	allowed []netip.Prefix
}

func (l *allowListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok && allowedClient(ta.AddrPort().Addr(), l.allowed) {
			return c, nil
		}
		c.Close()
	}
}
