package nsec3walker

import (
	"fmt"
	"hash/crc32"
	"os"
	"runtime"
	"strconv"
	"time"
)

const (
	charset       = "abcdefghijklmnopqrstuvwxyz0123456789"
	cntChanDomain = 2_000
)

type DomainGenerator struct {
	chanDomain  chan *Domain
	ranges      *RangeIndex
	out         *Output
	nsec3Params Nsec3Params
	counter     []int8
	chars       []rune
	len         int8
}

type Domain struct {
	Domain string
	Hash   string
}

func NewDomainGenerator(
	nsec3Domain string,
	nsec3Salt string,
	nsec3Iter uint16,
	ranges *RangeIndex,
	output *Output,
) (dg *DomainGenerator, err error) {
	n3p, err := NewNsec3Params(nsec3Domain, nsec3Salt, int(nsec3Iter))
	if err != nil {
		err = fmt.Errorf("invalid NSEC3 parameters: %w", err)
	}

	dg = &DomainGenerator{
		chanDomain:  make(chan *Domain, cntChanDomain),
		ranges:      ranges,
		out:         output,
		nsec3Params: n3p,
		counter:     []int8{0, 0, 0, 0}, // "aaaa"
		chars:       []rune(charset),
		len:         int8(len(charset)),
	}

	return
}

func (dg *DomainGenerator) Run(chanOut chan *Domain) {
	go dg.generateDomains()

	for i := 0; i < runtime.NumCPU(); i++ {
		go dg.hashWorker(chanOut)
	}
}

func (dg *DomainGenerator) hashWorker(chanOut chan *Domain) {
	var err error

	for domain := range dg.chanDomain {
		domain.Hash, err = dg.nsec3Params.CalculateHashForPrefix(domain.Domain)
		if err != nil {
			dg.out.Log("Error calculating NSEC3 hash for domain " + domain.Domain + ": " + err.Error())

			continue
		}

		inRange, _ := dg.ranges.isHashInRange(domain.Hash)

		if !inRange {
			chanOut <- &Domain{Domain: domain.Domain, Hash: domain.Hash}
		}
	}
}

func (dg *DomainGenerator) generateDomains() {
	suffix := dg.getRandomPrefix() + "." + dg.nsec3Params.domain

	for {
		dg.chanDomain <- &Domain{Domain: dg.toString() + suffix}
		dg.next()
	}
}

func (dg *DomainGenerator) increment(index int8) (flipped bool) {
	dg.counter[index]++

	if dg.counter[index] >= dg.len {
		dg.counter[index] = 0
		flipped = true
	}

	return
}

func (dg *DomainGenerator) next() {
	flipped := true
	var index int8 = 0

	for index < dg.positions() {
		flipped = dg.increment(index)

		if !flipped {
			return
		}

		index++
	}

	dg.counter = make([]int8, dg.positions()+1)
}

func (dg *DomainGenerator) positions() int8 {
	return int8(len(dg.counter))
}

func (dg *DomainGenerator) toString() string {
	result := make([]rune, len(dg.counter))

	for i, idx := range dg.counter {
		result[i] = dg.chars[idx]
	}

	return string(result)
}

func (dg *DomainGenerator) getRandomPrefix() (prefix string) {
	machineID := os.Getppid()
	pid := os.Getpid()
	timestamp := time.Now().UnixNano()
	prefix = strconv.Itoa(int(crc32.ChecksumIEEE([]byte(fmt.Sprintf("%d%d%d", machineID, pid, timestamp)))))

	return
}
