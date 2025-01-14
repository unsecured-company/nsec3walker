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
	prefix := getPrefix(hashStart)

	ri.mutex.RLock()
	existingStartVal, existsStart := ri.Index[prefix][hashStart]
	_, existsEnd = ri.Index[prefix][hashEnd]
	ri.mutex.RUnlock()

	existsAndDifferentEnd := existsStart && existingStartVal != "" && existingStartVal != hashEnd
	existsStartWithEmptyEnd := existsStart && existingStartVal == ""
	updateStartValue := !existsStart || existsStartWithEmptyEnd || (existsAndDifferentEnd && ri.ignoreChanges)

	if existsAndDifferentEnd {
		msg := "range starting %s already exists with different hashEnd! Existing: %s | New: %s"
		err = fmt.Errorf(msg, hashStart, existingStartVal, hashEnd)
	}

	if !existsStart {
		ri.cntChains.Add(1)
	}

	if existsStartWithEmptyEnd {
		ri.cntChainsEmpty.Add(-1)
	}

	if updateStartValue {
		ri.mutex.Lock()
		ri.Index[prefix][hashStart] = hashEnd
		ri.mutex.Unlock()
	}

	if !existsEnd {
		ri.mutex.Lock()
		ri.Index[prefix][hashEnd] = ""
		ri.cntChainsEmpty.Add(1)
		ri.mutex.Unlock()
	}

	return
}

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
