package nsec3walker

import (
	"encoding/base32"
	"math/big"
	"strings"
)

// nsec3HashBits is the width of a SHA-1 NSEC3 hash (RFC 5155) - the size of
// the ring domain hashes are placed on.
const nsec3HashBits = 160

var ringSize = new(big.Int).Lsh(big.NewInt(1), nsec3HashBits)

// hashToBigInt converts a lowercase base32hex-encoded NSEC3 hash (as stored
// throughout this package) into its numeric position on the hash ring.
func hashToBigInt(hash string) (*big.Int, bool) {
	raw, err := base32.HexEncoding.DecodeString(strings.ToUpper(hash))
	if err != nil {
		return nil, false
	}

	return new(big.Int).SetBytes(raw), true
}

// rangeLength returns the distance from start to end going forward around
// the ring, wrapping around if end comes numerically before start.
func rangeLength(start, end string) (*big.Int, bool) {
	s, ok := hashToBigInt(start)
	if !ok {
		return nil, false
	}

	e, ok := hashToBigInt(end)
	if !ok {
		return nil, false
	}

	length := new(big.Int).Sub(e, s)
	if length.Sign() < 0 {
		length.Add(length, ringSize)
	}

	return length, true
}

// CoveredLength returns the total ring distance spanned by fully known
// ranges, i.e. entries whose end hash has also been discovered.
func (ht *HashTree) CoveredLength() *big.Int {
	ht.mutex.RLock()
	defer ht.mutex.RUnlock()

	covered := new(big.Int)
	it := ht.tree.Iterator()

	for it.Next() {
		endHash := it.Value().(string)
		if endHash == "" {
			continue
		}

		if length, ok := rangeLength(it.Key().(string), endHash); ok {
			covered.Add(covered, length)
		}
	}

	return covered
}

// EstimateTotal predicts the total number of NSEC3-hashed names in the zone
// by extrapolating from how much of the ring has been covered so far:
// discovered hashes are ~uniformly distributed over the ring (being SHA-1
// output), so discovered / (covered ring fraction) approximates the total.
// The estimate is unstable until a meaningful fraction of the ring has been
// walked, since it's extrapolating from a small sample early on.
func (ri *RangeIndex) EstimateTotal(discovered int64) (estimatedTotal *big.Int, ok bool) {
	if discovered <= 0 {
		return nil, false
	}

	covered := ri.index.CoveredLength()
	if covered.Sign() <= 0 {
		return nil, false
	}

	estimatedTotal = new(big.Int).Mul(big.NewInt(discovered), ringSize)
	estimatedTotal.Div(estimatedTotal, covered)

	return estimatedTotal, true
}
