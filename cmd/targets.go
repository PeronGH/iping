package cmd

import (
	"bufio"
	"fmt"
	"math/bits"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go4.org/netipx"
)

// targetSet is a union of non-overlapping prefixes, indexed as one contiguous
// range [0, size) so it can be shuffled as a whole.
type targetSet struct {
	name     string
	slug     string // filesystem-safe base name for derived output files
	prefixes []netip.Prefix
	offsets  []uint64 // offsets[i] is the index of prefixes[i]'s first address
	size     uint64
}

// loadTargets parses arg as a CIDR or IP, falling back to a file with one per line.
func loadTargets(arg string) (*targetSet, error) {
	if prefix, err := parsePrefix(arg); err == nil {
		set, err := newTargetSet(arg, []netip.Prefix{prefix})
		if err != nil {
			return nil, err
		}
		set.slug = strings.NewReplacer("/", "_", ":", "-").Replace(arg)
		return set, nil
	}

	f, err := os.Open(arg)
	if err != nil {
		return nil, fmt.Errorf("target %q is neither a CIDR/IP nor a readable file: %w", arg, err)
	}
	defer f.Close()

	var prefixes []netip.Prefix
	scanner := bufio.NewScanner(f)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		prefix, err := parsePrefix(text)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", arg, line, err)
		}
		prefixes = append(prefixes, prefix)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", arg, err)
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("%s contains no targets", arg)
	}

	set, err := newTargetSet(arg, prefixes)
	if err != nil {
		return nil, err
	}
	unit := "ranges"
	if len(set.prefixes) == 1 {
		unit = "range"
	}
	set.name = fmt.Sprintf("%s (%d %s)", arg, len(set.prefixes), unit)
	set.slug = strings.TrimSuffix(filepath.Base(arg), filepath.Ext(arg))
	return set, nil
}

// parsePrefix accepts a CIDR or a single IP, treated as a full-length prefix.
func parsePrefix(s string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR or IP %q", s)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// newTargetSet merges overlapping prefixes so no address is probed twice.
func newTargetSet(name string, prefixes []netip.Prefix) (*targetSet, error) {
	var builder netipx.IPSetBuilder
	for _, prefix := range prefixes {
		builder.AddPrefix(prefix)
	}
	ipset, err := builder.IPSet()
	if err != nil {
		return nil, err
	}

	set := &targetSet{name: name, prefixes: ipset.Prefixes()}
	for _, prefix := range set.prefixes {
		hostBits := prefix.Addr().BitLen() - prefix.Bits()
		var carry uint64
		set.offsets = append(set.offsets, set.size)
		set.size, carry = bits.Add64(set.size, uint64(1)<<hostBits, 0)
		if hostBits >= 64 || carry != 0 {
			return nil, fmt.Errorf("target %s is too large: at most 2^64-1 addresses are supported", name)
		}
	}
	return set, nil
}

func (s *targetSet) addrAt(i uint64) netip.Addr {
	j, found := slices.BinarySearch(s.offsets, i)
	if !found {
		j--
	}
	return addrAt(s.prefixes[j].Addr(), i-s.offsets[j])
}
