package nsec3walker

import (
	"iter"
	"strconv"
	"sync"
	"sync/atomic"
)

type Cracked struct {
	cracked map[string]map[string]string
	// "cz|salt|iterations" -> "" -> "c17odk0qjlecpl8eldnctr21vpck06bq" -> "abtest"
	lock  sync.Mutex
	count atomic.Int64
}

func NewCracked() (cr *Cracked) {
	return &Cracked{
		cracked: make(map[string]map[string]string),
	}
}

func (cr *Cracked) Iterate() iter.Seq2[string, map[string]string] {
	return func(yield func(string, map[string]string) bool) {
		for key, hashes := range cr.cracked {
			yield(key, hashes)
		}
	}
}

func (cr *Cracked) Add(n3p Nsec3Params, hash string, domCracked string) {
	cr.lock.Lock()
	if _, ok := cr.cracked[n3p.key]; !ok {
		cr.cracked[n3p.key] = make(map[string]string)
	}

	cr.cracked[n3p.key][hash] = n3p.GetFullDomain(domCracked)
	cr.lock.Unlock()
	cr.count.Add(1)
}

func (cr *Cracked) AddFromHashcatParts(hash string, domRoot string, salt string, iterStr string, domCracked string) (err error) {
	var n3p Nsec3Params
	var iterInt int

	iterInt, err = strconv.Atoi(iterStr)
	if err == nil {
		n3p, err = NewNsec3Params(domRoot, salt, iterInt)
	}

	if err != nil {
		return
	}

	cr.Add(n3p, hash, domCracked)

	return
}

func (cr *Cracked) Get(n3p Nsec3Params, hash string) (plaintext string, ok bool) {
	cr.lock.Lock()
	_, ok = cr.cracked[n3p.key]

	if ok {
		plaintext, ok = cr.cracked[n3p.key][hash]
	}

	cr.lock.Unlock()

	return
}

func (cr *Cracked) GetForCsvItem(csvItem CsvItem) (plaintext string, ok bool, err error) {
	n3p, err := NewNsec3Params(csvItem.Domain, csvItem.Salt, csvItem.Iterations)
	if err != nil {
		return
	}

	plaintext, ok = cr.Get(n3p, csvItem.Hash)

	return
}

func (cr *Cracked) Count() int64 {
	return cr.count.Load()
}
