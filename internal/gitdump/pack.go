package gitdump

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// maxDeltaDepth bounds how long a chain of deltas may be before the read
// gives up. Git itself caps chains at 50 by default; anything much longer in a
// downloaded pack is malformed or hostile.
const maxDeltaDepth = 64

// packTypes maps the 3-bit type code in a pack entry header to its object
// type name. Codes 6 and 7 are deltas and are handled separately.
var packTypes = map[byte]string{1: "commit", 2: "tree", 3: "blob", 4: "tag"}

// pack is one downloaded pack file with its v2 index held in memory. The pack
// itself stays on disk and is read with ReadAt.
type pack struct {
	idx  []byte
	f    *os.File
	size int64
	n    uint32
}

// openPack loads a version-2 .idx and opens its .pack for reading. Anything
// that doesn't look like a v2 index is rejected.
func openPack(idxPath, packPath string) (*pack, error) {
	idx, err := os.ReadFile(idxPath)
	if err != nil {
		return nil, err
	}
	// A v2 index starts with the magic "\377tOc" and version 2, then the
	// 256-entry fanout table. Anything shorter than that can't be valid.
	if len(idx) < 8+1024 || !bytes.Equal(idx[:4], []byte{0xff, 't', 'O', 'c'}) || binary.BigEndian.Uint32(idx[4:8]) != 2 {
		return nil, fmt.Errorf("%s is not a v2 pack index", idxPath)
	}
	n := binary.BigEndian.Uint32(idx[8+4*255:])
	// The index holds, per object: a 20-byte name, a 4-byte CRC and a 4-byte
	// offset, plus a 8-byte large offset for any pack over 2 GiB; the trailing
	// 40 bytes are the pack and index checksums.
	if uint64(len(idx)) < 8+1024+uint64(n)*28+40 {
		return nil, fmt.Errorf("%s is truncated", idxPath)
	}
	f, err := os.Open(packPath)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &pack{idx: idx, f: f, size: st.Size(), n: n}, nil
}

// close releases the pack's file handle.
func (p *pack) close() {
	p.f.Close()
}

// offset looks up key in the index's sorted name table and returns where the
// object begins in the pack.
func (p *pack) offset(key [20]byte) (uint64, bool) {
	fanout := func(i int) uint32 { return binary.BigEndian.Uint32(p.idx[8+4*i:]) }
	lo := uint32(0)
	// The first bucket starts at zero; every other bucket starts where the previous fanout entry ends.
	if key[0] > 0 {
		lo = fanout(int(key[0]) - 1)
	}
	hi := fanout(int(key[0]))
	// A corrupt fanout table could point past the name table; clamping keeps
	// the search inside it.
	if hi > p.n {
		hi = p.n
	}
	if lo > hi {
		return 0, false
	}
	shaTable := 8 + 1024
	offsetTable := shaTable + 24*int(p.n)
	// Binary search within the bucket the fanout table selects for this first byte.
	for lo < hi {
		mid := (lo + hi) / 2
		at := shaTable + 20*int(mid)
		cmp := bytes.Compare(p.idx[at:at+20], key[:])
		if cmp == 0 {
			return p.offsetAt(offsetTable, mid), true
		}
		if cmp < 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return 0, false
}

// offsetAt reads the pack offset of the i-th object, following the
// large-offset indirection when the 4-byte value has its top bit set.
func (p *pack) offsetAt(offsetTable int, i uint32) uint64 {
	v := binary.BigEndian.Uint32(p.idx[offsetTable+4*int(i):])
	if v&0x80000000 == 0 {
		return uint64(v)
	}
	largeTable := offsetTable + 4*int(p.n)
	large := int(v & 0x7fffffff)
	// An index pointing past its large-offset table yields offset 0, which
	// readAt then rejects as a malformed object.
	if largeTable+8*large+8 > len(p.idx) {
		return 0
	}
	return binary.BigEndian.Uint64(p.idx[largeTable+8*large:])
}

// readAt returns the type and content of the object starting at off. Deltas
// are resolved recursively: OFS_DELTA bases are earlier in this same pack, and
// REF_DELTA bases are looked up by name through resolve.
func (p *pack) readAt(off uint64, resolve func(string) (string, []byte, error), depth int) (string, []byte, error) {
	if depth > maxDeltaDepth {
		return "", nil, fmt.Errorf("delta chain deeper than %d", maxDeltaDepth)
	}
	if off >= uint64(p.size) {
		return "", nil, fmt.Errorf("pack offset %d out of range", off)
	}
	br := bufio.NewReader(io.NewSectionReader(p.f, int64(off), p.size-int64(off)))

	c, err := br.ReadByte()
	if err != nil {
		return "", nil, err
	}
	typeCode := (c >> 4) & 7
	// The size is a little-endian varint in the header's low nibble plus
	// 7-bit groups; the high bit of each byte says whether another follows.
	size := uint64(c & 15)
	shift := uint(4)
	// Each pass reads one more size byte while the high bit says another follows.
	for c&0x80 != 0 {
		if c, err = br.ReadByte(); err != nil {
			return "", nil, err
		}
		size |= uint64(c&0x7f) << shift
		shift += 7
	}
	if size > maxObjectBytes {
		return "", nil, fmt.Errorf("packed object of %d bytes exceeds limit", size)
	}

	if typ, ok := packTypes[typeCode]; ok {
		data, err := inflate(br, size)
		return typ, data, err
	}

	var baseTyp string
	var baseData []byte
	switch typeCode {
	case 6:
		// OFS_DELTA: the base sits earlier in this pack, named by a backwards
		// offset in the same big-endian-7-bit-with-carry encoding git uses.
		c, err := br.ReadByte()
		if err != nil {
			return "", nil, err
		}
		rel := uint64(c & 0x7f)
		// Each pass reads one more offset byte, using the same encoding as the size.
		for c&0x80 != 0 {
			if c, err = br.ReadByte(); err != nil {
				return "", nil, err
			}
			rel = (rel+1)<<7 | uint64(c&0x7f)
		}
		if rel == 0 || rel > off {
			return "", nil, fmt.Errorf("invalid delta base offset")
		}
		if baseTyp, baseData, err = p.readAt(off-rel, resolve, depth+1); err != nil {
			return "", nil, err
		}
	case 7:
		// REF_DELTA: the base is named by its 20-byte object name, which may live
		// in another pack or be loose, so it goes back through the store.
		var raw [20]byte
		if _, err := io.ReadFull(br, raw[:]); err != nil {
			return "", nil, err
		}
		var err error
		if baseTyp, baseData, err = resolve(fmt.Sprintf("%x", raw)); err != nil {
			return "", nil, err
		}
	default:
		return "", nil, fmt.Errorf("unknown pack object type %d", typeCode)
	}

	delta, err := inflate(br, size)
	if err != nil {
		return "", nil, err
	}
	out, err := applyDelta(baseData, delta)
	return baseTyp, out, err
}

// inflate decompresses one zlib stream from r, requiring exactly size bytes.
func inflate(r io.Reader, size uint64) ([]byte, error) {
	zr, err := zlib.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out := make([]byte, size)
	if _, err := io.ReadFull(zr, out); err != nil {
		return nil, fmt.Errorf("inflating packed object: %w", err)
	}
	return out, nil
}

// applyDelta rebuilds a target object from base and a git delta. The delta is
// a list of instructions: copy a range of base, or insert literal bytes.
func applyDelta(base, delta []byte) ([]byte, error) {
	srcSize, delta, err := deltaVarint(delta)
	if err != nil {
		return nil, err
	}
	if srcSize != uint64(len(base)) {
		return nil, fmt.Errorf("delta base is %d bytes, delta expects %d", len(base), srcSize)
	}
	dstSize, delta, err := deltaVarint(delta)
	if err != nil {
		return nil, err
	}
	if dstSize > maxObjectBytes {
		return nil, fmt.Errorf("delta target of %d bytes exceeds limit", dstSize)
	}
	out := make([]byte, 0, dstSize)
	// Each pass consumes one instruction from the delta.
	for len(delta) > 0 {
		op := delta[0]
		delta = delta[1:]
		if op&0x80 != 0 {
			// Copy: the low four bits of op say which offset bytes follow, the
			// next three which size bytes. Absent bytes are zero.
			var off, size uint32
			// Each pass reads one offset byte that the opcode says is present.
			for i := 0; i < 4; i++ {
				if op&(1<<i) != 0 {
					if len(delta) == 0 {
						return nil, fmt.Errorf("delta truncated")
					}
					off |= uint32(delta[0]) << (8 * i)
					delta = delta[1:]
				}
			}
			// Each pass reads one size byte that the opcode says is present.
			for i := 0; i < 3; i++ {
				if op&(0x10<<i) != 0 {
					if len(delta) == 0 {
						return nil, fmt.Errorf("delta truncated")
					}
					size |= uint32(delta[0]) << (8 * i)
					delta = delta[1:]
				}
			}
			// A size of zero means 0x10000, which is how git encodes the largest copy.
			if size == 0 {
				size = 0x10000
			}
			if uint64(off)+uint64(size) > uint64(len(base)) {
				return nil, fmt.Errorf("delta copy out of range")
			}
			out = append(out, base[off:off+size]...)
		} else if op != 0 {
			// Insert: the opcode is the literal byte count to copy from the delta.
			n := int(op)
			if n > len(delta) {
				return nil, fmt.Errorf("delta insert truncated")
			}
			out = append(out, delta[:n]...)
			delta = delta[n:]
		} else {
			return nil, fmt.Errorf("delta opcode 0 is reserved")
		}
	}
	if uint64(len(out)) != dstSize {
		return nil, fmt.Errorf("delta produced %d bytes, expected %d", len(out), dstSize)
	}
	return out, nil
}

// deltaVarint reads one little-endian base-128 size from the front of a delta.
func deltaVarint(b []byte) (uint64, []byte, error) {
	var v uint64
	var shift uint
	// Each pass consumes one byte of the varint until the high bit is clear.
	for i := 0; ; i++ {
		if i >= len(b) {
			return 0, nil, fmt.Errorf("delta size truncated")
		}
		v |= uint64(b[i]&0x7f) << shift
		shift += 7
		if b[i]&0x80 == 0 {
			return v, b[i+1:], nil
		}
	}
}
