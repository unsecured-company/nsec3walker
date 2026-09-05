package nsec3walker

import (
	"fmt"
	"math/rand"
	"runtime"
	"testing"
)

func TestHashTree_GetLastRange(t *testing.T) {
	ht := NewHashTree()

	if k, v := ht.GetLastRange(); k != "" || v != "" {
		t.Fatalf("empty tree: got (%q, %q), want (\"\", \"\")", k, v)
	}

	ht.Add("b", "bEnd")
	ht.Add("a", "aEnd")
	ht.Add("c", "cEnd")

	if k, v := ht.GetLastRange(); k != "c" || v != "cEnd" {
		t.Fatalf("got (%q, %q), want (\"c\", \"cEnd\")", k, v)
	}
}

func TestHashTree_ClosestBefore(t *testing.T) {
	ht := NewHashTree()

	if _, _, found := ht.ClosestBefore("m"); found {
		t.Fatal("empty tree: expected found=false")
	}

	ht.Add("b", "d")
	ht.Add("d", "f")
	ht.Add("f", "")

	tests := []struct {
		name      string
		input     string
		wantStart string
		wantEnd   string
		wantFound bool
	}{
		{"before smallest key", "a", "", "", false},
		{"strictly between b and d", "c", "b", "d", true},
		{"strictly between d and f", "e", "d", "f", true},
		{"after largest key", "z", "f", "", true},
		{"exact match on middle key", "d", "d", "f", true},
		{"exact match on smallest key", "b", "b", "d", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, found := ht.ClosestBefore(tt.input)
			if found != tt.wantFound {
				t.Fatalf("found = %v, want %v", found, tt.wantFound)
			}
			if !tt.wantFound {
				return
			}
			if start != tt.wantStart || end != tt.wantEnd {
				t.Fatalf("got (%q, %q), want (%q, %q)", start, end, tt.wantStart, tt.wantEnd)
			}
		})
	}
}

func TestRangeIndex_Add(t *testing.T) {
	ri := NewRangeIndex()

	existsStart, existsEnd, setFull, err := ri.Add("a", "b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if existsStart || existsEnd || !setFull {
		t.Fatalf("brand new range: existsStart=%v existsEnd=%v setFull=%v, want false/false/true", existsStart, existsEnd, setFull)
	}
	if got := ri.cntEndWithoutStart.Load(); got != 1 {
		t.Fatalf("cntEndWithoutStart = %d, want 1", got)
	}

	// "b" was only known as a dangling end; linking it as a start should
	// resolve it and leave "c" as the new dangling end.
	existsStart, existsEnd, setFull, err = ri.Add("b", "c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !existsStart || existsEnd || !setFull {
		t.Fatalf("resolving dangling end: existsStart=%v existsEnd=%v setFull=%v, want true/false/true", existsStart, existsEnd, setFull)
	}
	if got := ri.cntEndWithoutStart.Load(); got != 1 {
		t.Fatalf("cntEndWithoutStart = %d, want 1 (b resolved, c dangling)", got)
	}

	// Re-adding an identical range is idempotent: no error, nothing new set.
	existsStart, _, setFull, err = ri.Add("a", "b")
	if err != nil {
		t.Fatalf("re-adding identical range should not error: %v", err)
	}
	if !existsStart || setFull {
		t.Fatalf("re-adding identical range: existsStart=%v setFull=%v, want true/false", existsStart, setFull)
	}

	// A conflicting end for an already-known start must error.
	if _, _, _, err = ri.Add("a", "zzz"); err == nil {
		t.Fatal("expected error when hashStart already exists with a different hashEnd")
	}
}

func TestRangeIndex_isHashInRange(t *testing.T) {
	ri := NewRangeIndex()
	ri.Add("b", "d")
	ri.Add("d", "f")
	ri.Add("f", "b") // closes the ring

	tests := []struct {
		name    string
		hash    string
		inRange bool
	}{
		{"middle of b-d", "c", true},
		{"middle of d-f", "e", true},
		{"wraps past the end", "z", true},
		{"wraps before the start", "a", true},
		{"boundary hash d", "d", true},
		// "f" is the wrap-around range's own start key: ClosestBefore's floor
		// lookup finds f -> b directly, whose end ("b") is lexicographically
		// smaller than "f" itself, so this must be caught by the wrap-around
		// check in isHashInRange rather than the plain hash<=end comparison.
		{"boundary hash f (wrap-around range's own start)", "f", true},
		{"boundary hash b (smallest key, ring start)", "b", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inRange, _, _ := ri.isHashInRange(tt.hash)
			if inRange != tt.inRange {
				t.Errorf("isHashInRange(%q) = %v, want %v", tt.hash, inRange, tt.inRange)
			}
		})
	}
}

// TestRangeIndex_isHashInRange_UncoveredGap checks that a hash which falls
// strictly outside any known range is correctly reported as not covered.
func TestRangeIndex_isHashInRange_UncoveredGap(t *testing.T) {
	ri := NewRangeIndex()
	ri.Add("m", "p") // only one range known; "p" is a dangling end

	if inRange, _, _ := ri.isHashInRange("q"); inRange {
		t.Fatal("hash after the only known range's dangling end should not be in range")
	}
}

func TestRangeIndex_isFinished(t *testing.T) {
	t.Run("incomplete: dangling end", func(t *testing.T) {
		ri := NewRangeIndex()
		ri.Add("b", "d")
		if ri.isFinished() {
			t.Fatal("expected not finished while an end has no matching start")
		}
	})

	t.Run("complete ring", func(t *testing.T) {
		ri := NewRangeIndex()
		ri.Add("b", "d")
		ri.Add("d", "f")
		ri.Add("f", "b")
		if !ri.isFinished() {
			t.Fatal("expected finished once the ring closes")
		}
	})

	t.Run("two disjoint closed loops are not one ring", func(t *testing.T) {
		ri := NewRangeIndex()
		ri.Add("m", "p")
		ri.Add("p", "m") // closes loop 1: m -> p -> m
		ri.Add("x", "y")
		ri.Add("y", "x") // closes loop 2: x -> y -> x

		if ri.cntEndWithoutStart.Load() != 0 {
			t.Fatalf("cntEndWithoutStart = %d, want 0 (every end was resolved)", ri.cntEndWithoutStart.Load())
		}
		if ri.isFinished() {
			t.Fatal("two separate closed loops must not be reported as one finished ring")
		}
	})
}

// BenchmarkRangeIndex_isHashInRange measures lookup cost as the number of
// already-discovered ranges grows, which is the relevant cost near the end
// of a walk when almost every generated candidate must be checked against a
// large, mostly-complete range index.
func BenchmarkRangeIndex_isHashInRange(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("ranges=%d", n), func(b *testing.B) {
			ri := NewRangeIndex()

			keys := make([]string, n)
			for i := 0; i < n; i++ {
				keys[i] = fmt.Sprintf("%08x", i)
			}
			for i := 0; i < n; i++ {
				ri.Add(keys[i], keys[(i+1)%n])
			}

			r := rand.New(rand.NewSource(1))
			queries := make([]string, b.N)
			for i := range queries {
				queries[i] = fmt.Sprintf("%08x", r.Intn(n))
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ri.isHashInRange(queries[i])
			}
		})
	}
}

// BenchmarkRangeIndex_isHashInRange_Miss complements
// BenchmarkRangeIndex_isHashInRange: instead of querying keys guaranteed to
// already be covered (the late-walk case), it queries uniformly across the
// full hash space while only a narrow band of it is populated - modeling
// early/mid-walk, where the index is still sparse and most generated
// candidates do NOT fall in any known range yet. This exercises the code
// path in isHashInRange that falls through both the wrap-around check and
// the hash<=closestEnd check, which the hit-only benchmark never reaches.
func BenchmarkRangeIndex_isHashInRange_Miss(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("ranges=%d", n), func(b *testing.B) {
			ri := NewRangeIndex()

			keys := make([]string, n)
			for i := 0; i < n; i++ {
				keys[i] = fmt.Sprintf("%08x", i)
			}
			for i := 0; i < n; i++ {
				ri.Add(keys[i], keys[(i+1)%n])
			}

			r := rand.New(rand.NewSource(1))
			queries := make([]string, b.N)
			for i := range queries {
				queries[i] = fmt.Sprintf("%08x", r.Uint32())
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ri.isHashInRange(queries[i])
			}
		})
	}
}

// BenchmarkRangeIndex_Add measures the cost of adding a new range (which
// includes the incremental ring-completion bookkeeping in mergeChain) once a
// large number of ranges are already chained together. It should stay flat
// as n grows - the old allRangesComplete() full-tree rescan on every Add
// would instead have made this scale linearly with n.
func BenchmarkRangeIndex_Add(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("ranges=%d", n), func(b *testing.B) {
			ri := NewRangeIndex()

			keys := make([]string, n)
			for i := 0; i < n; i++ {
				keys[i] = fmt.Sprintf("%08x", i)
			}
			for i := 0; i < n-1; i++ {
				ri.Add(keys[i], keys[i+1])
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				k1 := fmt.Sprintf("extra-%08x-a", i)
				k2 := fmt.Sprintf("extra-%08x-b", i)
				ri.Add(k1, k2)
			}
		})
	}
}

// BenchmarkRangeIndex_Concurrent mirrors how RunWalk actually drives a
// RangeIndex: many hash-worker goroutines call isHashInRange (RLock-only,
// via HashTree.mutex) far more often than the handful of per-NS goroutines
// that call Add (which additionally takes addMutex). It measures lock
// contention between readers and writers under GOMAXPROCS-wide concurrency,
// which the single-goroutine benchmarks above can't surface.
func BenchmarkRangeIndex_Concurrent(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("ranges=%d", n), func(b *testing.B) {
			ri := NewRangeIndex()

			keys := make([]string, n)
			for i := 0; i < n; i++ {
				keys[i] = fmt.Sprintf("%08x", i)
			}
			for i := 0; i < n; i++ {
				ri.Add(keys[i], keys[(i+1)%n])
			}

			// Reserve one of every runtime.NumCPU() parallel goroutines to
			// be a writer, approximating the walker's ratio of many
			// hash-checking workers to few NS-querying workers.
			writerStride := runtime.NumCPU()
			if writerStride < 2 {
				writerStride = 2
			}

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				r := rand.New(rand.NewSource(rand.Int63()))
				isWriter := r.Intn(writerStride) == 0
				i := 0
				for pb.Next() {
					if isWriter {
						k1 := fmt.Sprintf("extra-%08x-%08x-a", i, r.Int63())
						k2 := fmt.Sprintf("extra-%08x-%08x-b", i, r.Int63())
						ri.Add(k1, k2)
					} else {
						ri.isHashInRange(fmt.Sprintf("%08x", r.Intn(n)))
					}
					i++
				}
			})
		})
	}
}
