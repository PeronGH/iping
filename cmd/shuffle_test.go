package cmd

import (
	"net/netip"
	"testing"
)

func TestShuffledAddrsCoversTargetsOnce(t *testing.T) {
	cases := [][]string{
		{"10.1.2.3/32"},
		{"10.1.2.0/31"},
		{"10.1.2.0/23"},
		{"10.1.0.0/16"},
		{"2001:db8::/115"},
		{"10.0.0.0/30", "10.0.0.8/29", "192.168.1.7/32", "2001:db8::/126"},
		{"10.0.0.0/24", "10.0.0.128/25", "10.0.0.5/32", "10.0.1.0/26"},
	}
	for _, c := range cases {
		var prefixes []netip.Prefix
		want := map[netip.Addr]bool{}
		for _, s := range c {
			prefix := netip.MustParsePrefix(s)
			prefixes = append(prefixes, prefix)
			for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
				want[addr] = true
			}
		}
		set, err := newTargetSet("test", prefixes)
		if err != nil {
			t.Fatalf("%v: %v", c, err)
		}

		seen := map[netip.Addr]bool{}
		for addr := range shuffledAddrs(set) {
			if !want[addr] {
				t.Fatalf("%v: %s is outside the targets", c, addr)
			}
			if seen[addr] {
				t.Fatalf("%v: %s yielded twice", c, addr)
			}
			seen[addr] = true
		}
		if len(seen) != len(want) {
			t.Fatalf("%v: got %d addresses, want %d", c, len(seen), len(want))
		}
	}
}
