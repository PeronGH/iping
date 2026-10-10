package cmd

import (
	"encoding/binary"
	"iter"
	"math/bits"
	"math/rand/v2"
	"net/netip"
)

const feistelRounds = 4

// permutation is a keyed bijection on [0, size), computed in O(1) memory
// so ranges can be shuffled without materializing them.
type permutation struct {
	last     uint64
	halfBits uint
	halfMask uint64
	keys     [feistelRounds]uint64
}

func newPermutation(size uint64) permutation {
	last := size - 1
	halfBits := uint(bits.Len64(last)+1) / 2
	p := permutation{
		last:     last,
		halfBits: halfBits,
		halfMask: uint64(1)<<halfBits - 1,
	}
	for i := range p.keys {
		p.keys[i] = rand.Uint64()
	}
	return p
}

// at maps i in [0, size) to a unique value in the same range. The Feistel
// network permutes a possibly larger even-bit domain, so out-of-range outputs
// are re-encrypted until they land in range (cycle walking).
func (p permutation) at(i uint64) uint64 {
	x := i
	for {
		x = p.encrypt(x)
		if x <= p.last {
			return x
		}
	}
}

func (p permutation) encrypt(x uint64) uint64 {
	l, r := x>>p.halfBits, x&p.halfMask
	for _, key := range p.keys {
		l, r = r, l^(mix(r^key)&p.halfMask)
	}
	return l<<p.halfBits | r
}

// mix is the splitmix64 finalizer.
func mix(x uint64) uint64 {
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	x *= 0xc4ceb9fe1a85ec53
	x ^= x >> 33
	return x
}

func shuffledAddrs(set *targetSet) iter.Seq[netip.Addr] {
	perm := newPermutation(set.size)
	return func(yield func(netip.Addr) bool) {
		for i := uint64(0); ; i++ {
			if !yield(set.addrAt(perm.at(i))) || i == perm.last {
				return
			}
		}
	}
}

// addrAt returns base with offset in its host bits; base must be masked and
// offset must fit in the host bits, which must be fewer than 64.
func addrAt(base netip.Addr, offset uint64) netip.Addr {
	if base.Is4() {
		b := base.As4()
		binary.BigEndian.PutUint32(b[:], binary.BigEndian.Uint32(b[:])|uint32(offset))
		return netip.AddrFrom4(b)
	}
	b := base.As16()
	binary.BigEndian.PutUint64(b[8:], binary.BigEndian.Uint64(b[8:])|offset)
	return netip.AddrFrom16(b)
}
