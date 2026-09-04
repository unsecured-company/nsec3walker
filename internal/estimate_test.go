package nsec3walker

import (
	"encoding/base32"
	"math/big"
	"strings"
	"testing"
)

// bigIntToHash encodes n (0 <= n < ringSize) as a lowercase base32hex NSEC3
// hash string, the inverse of hashToBigInt. Used to build hash strings with
// known, exact positions on the ring for testing.
func bigIntToHash(n *big.Int) string {
	buf := make([]byte, 20)
	n.FillBytes(buf)

	return strings.ToLower(base32.HexEncoding.EncodeToString(buf))
}

func TestRangeLength(t *testing.T) {
	zero := bigIntToHash(big.NewInt(0))
	one := bigIntToHash(big.NewInt(1))
	max := bigIntToHash(new(big.Int).Sub(ringSize, big.NewInt(1)))

	t.Run("simple forward span", func(t *testing.T) {
		got, ok := rangeLength(zero, one)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if got.Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("got %s, want 1", got)
		}
	})

	t.Run("zero-width range", func(t *testing.T) {
		got, ok := rangeLength(one, one)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if got.Sign() != 0 {
			t.Fatalf("got %s, want 0", got)
		}
	})

	t.Run("wraps around the ring", func(t *testing.T) {
		// max -> zero is a single step forward (wrapping past the top of the ring)
		got, ok := rangeLength(max, zero)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if got.Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("got %s, want 1", got)
		}
	})

	t.Run("invalid hash", func(t *testing.T) {
		if _, ok := rangeLength("not-base32hex!!", one); ok {
			t.Fatal("expected ok=false for invalid input")
		}
	})
}

func TestRangeIndex_EstimateTotal(t *testing.T) {
	t.Run("no data yet", func(t *testing.T) {
		ri := NewRangeIndex()

		if _, ok := ri.EstimateTotal(0); ok {
			t.Fatal("expected ok=false with zero discovered")
		}

		ri.Add(bigIntToHash(big.NewInt(0)), "")
		if _, ok := ri.EstimateTotal(1); ok {
			t.Fatal("expected ok=false with no fully-known range yet")
		}
	})

	t.Run("extrapolates from a half-covered ring", func(t *testing.T) {
		// Split the ring into 8 equal segments and mark the first 4 of them
		// (half the ring) as fully discovered, chained ranges.
		seg := new(big.Int).Div(ringSize, big.NewInt(8))
		point := func(k int64) string {
			return bigIntToHash(new(big.Int).Mul(seg, big.NewInt(k)))
		}

		ri := NewRangeIndex()
		for k := int64(0); k < 4; k++ {
			if _, _, _, err := ri.Add(point(k), point(k+1)); err != nil {
				t.Fatalf("Add: %v", err)
			}
		}

		// 5 distinct hashes discovered (point(0)..point(4)) covering half the
		// ring => the other half should hold roughly as many again.
		estimatedTotal, ok := ri.EstimateTotal(5)
		if !ok {
			t.Fatal("expected ok=true")
		}

		want := big.NewInt(10)
		if estimatedTotal.Cmp(want) != 0 {
			t.Fatalf("got %s, want %s", estimatedTotal, want)
		}
	})
}
