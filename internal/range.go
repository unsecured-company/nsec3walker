package nsec3walker

import (
	"fmt"
	"sync"
	"sync/atomic"
)

/**
Format:
[first-two-chars-of-hash]: [start-hash] = end-hash
[a1]: [a1xxxx1]=a1xxxx1
[a1]: [a1xxxx2]=yyyyyyy
*/

const RangePrefixSize = 2

type RangeIndex struct {
	Index          map[string]map[string]string
	cntChains      atomic.Int64
	cntChainsEmpty atomic.Int64
	ignoreChanges  bool
	mutex          sync.RWMutex
}

func NewRangeIndex() (rangeIndex *RangeIndex) {
	rangeIndex = &RangeIndex{
		Index: make(map[string]map[string]string),
	}

	// NSEC3 are encoded in Base32
	base32chars := "0123456789abcdefghijklmnopqrstuv"

	for _, char1 := range base32chars {
		for _, char2 := range base32chars {
			prefix := string([]rune{char1, char2})
			rangeIndex.Index[prefix] = make(map[string]string)
		}
	}

	return
}

func getPrefix(hash string) string {
	return hash[:RangePrefixSize]
}

func (ri *RangeIndex) Add(hashStart string, hashEnd string) (existsStart bool, existsEnd bool, err error) {
	/**
	If hashStart key already exists, check the value didn't change (hashEnd)
	If hashEnd does not exists, add it with empty value
	*/
	prefixStart := getPrefix(hashStart)
	prefixEnd := getPrefix(hashEnd)

	ri.mutex.RLock()
	existingStartValAsStart, existsStart := ri.Index[prefixStart][hashStart]
	_, existsEnd = ri.Index[prefixEnd][hashEnd]
	ri.mutex.RUnlock()

	// !existsStart = adding full chain from start to end
	// !existsEnd adding end of chan as start with empty end

	// existsAndDifferentEnd = start exists and end is different
	existsAndDifferentEnd := existsStart && existingStartValAsStart != "" && existingStartValAsStart != hashEnd
	// existsStartWithEmptyEnd = start exists and end is empty, from being End before
	existsStartWithEmptyEnd := existsStart && existingStartValAsStart == ""
	updateStartValue := !existsStart || existsStartWithEmptyEnd || (existsAndDifferentEnd && ri.ignoreChanges)

	if existsAndDifferentEnd {
		msg := "range starting %s already exists with different hashEnd! Existing: %s | New: %s"
		err = fmt.Errorf(msg, hashStart, existingStartValAsStart, hashEnd)
	}

	/*
		debugging the brain-work here
		if !existsStart && !existsEnd {
			log.Printf("Adding range %s - %s\n", hashStart, hashEnd)
		} else {
			log.Printf("both exists %s - %s\n", hashStart, hashEnd)
		}

		msg := "existsStart %v | existsEnd %v | existsAndDifferentEnd %v | existsStartWithEmptyEnd %v | updateStartValue %v\n"
		log.Printf(msg, existsStart, existsEnd, existsAndDifferentEnd, existsStartWithEmptyEnd, updateStartValue)
	*/

	if !existsStart {
		ri.cntChains.Add(1)
	}

	if existsStartWithEmptyEnd {
		ri.cntChainsEmpty.Add(-1)
	}

	if updateStartValue {
		ri.mutex.Lock()
		ri.Index[prefixStart][hashStart] = hashEnd
		ri.mutex.Unlock()
	}

	if !existsEnd {
		ri.mutex.Lock()
		ri.Index[prefixEnd][hashEnd] = ""
		ri.cntChainsEmpty.Add(1)
		ri.mutex.Unlock()
	}

	return
}

// isHashInRange determines whether a given hash falls within any of the stored hash ranges.
//
// This function may produce false negatives in specific edge cases where the zone of hashes
// is very small or spans across prefix boundaries. For example, consider a saved range with
// a prefix starting at "10..." and ending at "30...", and we are looking for a hash "20...".
// If the prefix derived from the hash is "20", the function might not find a match due to
// how ranges are indexed by prefix.
// However, as this function is only used to avoid querying domains whose hashes are already
// within the known ranges, these false negatives are acceptable for its intended purpose.
// If I get bored I will rewrite it to binary search.
func (ri *RangeIndex) isHashInRange(hash string) (inRange bool, exactRange string) {
	prefix := getPrefix(hash)

	ri.mutex.RLock()
	defer ri.mutex.RUnlock()

	ranges, _ := ri.Index[prefix]

	for start, end := range ranges {
		if start <= hash && hash <= end {
			exactRange = start + "=" + end

			return true, exactRange
		}
	}

	return
}
