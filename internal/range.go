package nsec3walker

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"

	rbt "github.com/emirpasic/gods/trees/redblacktree"
)

type HashTree struct {
	tree  *rbt.Tree
	mutex sync.RWMutex
}

type RangeIndex struct {
	index              *HashTree
	cntEndWithoutStart atomic.Int64
	ignoreChanges      bool
	addMutex           sync.Mutex

	// Incremental ring-completion tracking (guarded by addMutex, updated
	// only from Add): chainStartEnd/chainEndStart record the currently
	// known maximal chains of linked-together full ranges, keyed by their
	// start and end hash respectively. cntChains counts how many such
	// disjoint chains currently exist. The ring is complete once there is
	// exactly one chain left and it wraps around onto itself (its start
	// equals its end) with no dangling ends - see mergeChain.
	chainStartEnd map[string]string
	chainEndStart map[string]string
	cntChains     int
	finished      atomic.Bool
}

func NewHashTree() (hashTree *HashTree) {
	hashTree = &HashTree{
		tree: rbt.NewWithStringComparator(),
	}
	return
}

func NewRangeIndex() (rangeIndex *RangeIndex) {
	rangeIndex = &RangeIndex{
		index:         NewHashTree(),
		chainStartEnd: make(map[string]string),
		chainEndStart: make(map[string]string),
	}
	return
}

func (ht *HashTree) Add(key, val string) {
	ht.mutex.Lock()
	defer ht.mutex.Unlock()
	ht.tree.Put(key, val)
}

func (ht *HashTree) Get(key string) (value string, exists bool) {
	ht.mutex.RLock()
	defer ht.mutex.RUnlock()
	valInterface, exists := ht.tree.Get(key)
	if exists {
		value = valInterface.(string)
	}
	return
}

func (ht *HashTree) GetLastRange() (key, val string) {
	ht.mutex.RLock()
	defer ht.mutex.RUnlock()
	lastNode := ht.tree.Right()
	if lastNode != nil {
		return lastNode.Key.(string), lastNode.Value.(string)
	}
	return
}

func (ht *HashTree) PrintAll() {
	ht.mutex.RLock()
	defer ht.mutex.RUnlock()
	iterator := ht.tree.Iterator()
	for iterator.Next() {
		log.Printf("Range %s => %s", iterator.Key().(string), iterator.Value().(string))
	}
}

// ClosestBefore returns the range that starts with the largest key less than
// or equal to the input hash (the tree's floor), in O(log n).
func (ht *HashTree) ClosestBefore(input string) (startHash string, endHash string, found bool) {
	ht.mutex.RLock()
	defer ht.mutex.RUnlock()
	node, ok := ht.tree.Floor(input)
	if !ok {
		return
	}
	startHash = node.Key.(string)
	endHash = node.Value.(string)
	found = true
	return
}

// isInRange tries the cheap wrap-around check before the O(log n) Floor traversal, since it alone resolves most queries late in a walk.
func (ht *HashTree) isInRange(hash string) (inRange bool, rangeStart string, rangeEnd string) {
	ht.mutex.RLock()
	defer ht.mutex.RUnlock()

	if lastNode := ht.tree.Right(); lastNode != nil {
		lastHash := lastNode.Key.(string)
		lastVal := lastNode.Value.(string)
		if lastVal != "" && lastVal < lastHash && (hash <= lastVal || hash >= lastHash) {
			return true, lastHash, lastVal
		}
	}

	if node, ok := ht.tree.Floor(hash); ok {
		closestStart := node.Key.(string)
		closestEnd := node.Value.(string)
		if hash <= closestEnd {
			return true, closestStart, closestEnd
		}
	}

	return
}

func (ri *RangeIndex) PrintAll() {
	ri.index.PrintAll()
}

func (ri *RangeIndex) Add(hashStart string, hashEnd string) (existsStart bool, existsEnd bool, setFull bool, err error) {
	/**
	If hashStart key already exists, check the value didn't change (hashEnd)
	If hashEnd does not exists, add it with empty value
	*/
	ri.addMutex.Lock() // this mutex is for ensuring correct values of cntChains and cntEndWithoutStart
	existingStartValAsStart, existsStart := ri.index.Get(hashStart)
	_, existsEnd = ri.index.Get(hashEnd)

	// !existsStart = adding full chain from start to end
	// !existsEnd adding end of chan as start with empty end

	// existsAndDifferentEnd = start exists and end is different
	existsAndDifferentEnd := existsStart && existingStartValAsStart != "" && existingStartValAsStart != hashEnd
	if existsAndDifferentEnd {
		msg := "range starting %s already exists with different hashEnd! Existing: %s | New: %s"
		err = fmt.Errorf(msg, hashStart, existingStartValAsStart, hashEnd)

		if !ri.ignoreChanges {
			ri.addMutex.Unlock()

			return
		}
	}

	// existsStartWithEmptyEnd = start exists and end is empty, from being End before
	existsStartWithEmptyEnd := existsStart && existingStartValAsStart == ""
	setFull = !existsStart || existsStartWithEmptyEnd

	if existsStartWithEmptyEnd {
		ri.cntEndWithoutStart.Add(-1)
	}

	if setFull {
		ri.index.Add(hashStart, hashEnd)
	}

	if !existsEnd {
		ri.cntEndWithoutStart.Add(1)
		ri.index.Add(hashEnd, "")
	}

	if setFull {
		ri.mergeChain(hashStart, hashEnd)
	}

	ri.addMutex.Unlock()

	return
}

// mergeChain incrementally maintains the set of maximal chains formed by
// linking together full (hashStart, hashEnd) ranges as they're discovered,
// so isFinished can answer in O(1) instead of rescanning the whole tree.
// Must be called with addMutex held, once per newly-established full range.
func (ri *RangeIndex) mergeChain(start, end string) {
	newStart, newEnd := start, end
	merged := false

	// Some existing chain starts exactly where this range ends - append it.
	if nextEnd, ok := ri.chainStartEnd[newEnd]; ok {
		delete(ri.chainStartEnd, newEnd)
		delete(ri.chainEndStart, nextEnd)
		newEnd = nextEnd
		merged = true
	}

	// Some existing chain ends exactly where this range starts - prepend it.
	if prevStart, ok := ri.chainEndStart[newStart]; ok {
		delete(ri.chainEndStart, newStart)
		delete(ri.chainStartEnd, prevStart)

		if merged {
			// This range bridged two previously-separate chains into one.
			ri.cntChains--
		}

		newStart = prevStart
		merged = true
	}

	if !merged {
		ri.cntChains++
	}

	ri.chainStartEnd[newStart] = newEnd
	ri.chainEndStart[newEnd] = newStart

	ri.finished.Store(ri.cntChains == 1 && newStart == newEnd && ri.cntEndWithoutStart.Load() == 0)
}

// isHashInRange reports whether hash falls in a discovered range; discard rangeStart/rangeEnd if unused rather than formatting them.
func (ri *RangeIndex) isHashInRange(hash string) (inRange bool, rangeStart string, rangeEnd string) {
	return ri.index.isInRange(hash)
}

func (ri *RangeIndex) isFinished() bool {
	return ri.finished.Load()
}

// DebugState reports the internal ring-completion bookkeeping for
// diagnostics (e.g. periodic stats logging): how many disjoint chains of
// linked ranges currently exist and how many ends are still dangling
// (discovered but with no range starting there yet).
func (ri *RangeIndex) DebugState() (cntChains int, cntEndWithoutStart int64) {
	ri.addMutex.Lock()
	defer ri.addMutex.Unlock()

	return ri.cntChains, ri.cntEndWithoutStart.Load()
}
