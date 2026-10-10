package cmd

import (
	"net/netip"
	"testing"
)

func TestShuffledAddrsCoversPrefixOnce(t *testing.T) {
	for _, s := range []string{"10.1.2.3/32", "10.1.2.0/31", "10.1.2.0/23", "10.1.0.0/16", "2001:db8::/115"} {
		prefix := netip.MustParsePrefix(s)
		size := 1 << (prefix.Addr().BitLen() - prefix.Bits())
		seen := make(map[netip.Addr]bool, size)
		for addr := range shuffledAddrs(prefix) {
			if !prefix.Contains(addr) {
				t.Fatalf("%s: %s is outside the prefix", s, addr)
			}
			if seen[addr] {
				t.Fatalf("%s: %s yielded twice", s, addr)
			}
			seen[addr] = true
		}
		if len(seen) != size {
			t.Fatalf("%s: got %d addresses, want %d", s, len(seen), size)
		}
	}
}
