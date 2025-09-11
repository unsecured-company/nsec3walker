package nsec3walker

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	WaitMs         = 100
	sizeChanDomain = 500
	ErrorBlackLies = "black_lies"
	ErrorWhiteLies = "white_lies"
)

type NSec3Walker struct {
	config       *Config
	stats        *Stats
	ranges       *RangeIndex
	out          *Output
	nsec         Nsec3Params
	cntNsWorkers int

	chanDomain      chan *Domain
	chanHashesFound chan Nsec3Record
	chanHashesNew   chan string
}

type Nsec3Record struct {
	Start string
	End   string
	Types []uint16
}

func NewNSec3Walker(config *Config) (nsecWalker *NSec3Walker) {
	stats := NewStats(config.Output)

	nsecWalker = &NSec3Walker{
		config:          config,
		chanHashesFound: make(chan Nsec3Record, 1000),
		ranges:          NewRangeIndex(),
		out:             config.Output,
		stats:           stats,
	}

	nsecWalker.nsec.domain = config.Domain

	return
}

func (nw *NSec3Walker) RunDebug() (err error) {
	err = nw.config.processAuthNsServers(true)

	if err != nil {
		return
	}

	domain := nw.config.Domain
	nw.out.Log("Showing debug data for domain: " + domain)
	nw.out.Log(fmt.Sprintf("NS servers to walk: %v", nw.config.DomainDnsServers))

	for _, ns := range nw.config.DomainDnsServers {
		r, err := getNsResponse(domain, ns)

		fmt.Printf("[%s] @ [%s]\n===Err===\n%v\n\n===Response===\n%s\n\n\n", domain, ns, err, r)

		if err != nil {
			continue
		}

		fmt.Println("NSEC3 hashes")

		for _, rr := range r.Ns {
			if nsec3, ok := rr.(*dns.NSEC3); ok {
				first := strings.Split(nsec3.Header().Name, ".")[0]
				fmt.Println(first + ";" + strings.ToLower(nsec3.NextDomain))
			}
		}
	}

	return
}

func (nw *NSec3Walker) RunCrack() (err error) {
	cracking := NewCracking(nw.config, nw.out)
	err = cracking.Run()

	return
}

func (nw *NSec3Walker) RunWalk() (err error) {
	err = nw.config.processAuthNsServers(false)

	if err != nil {
		return
	}

	nw.out.Log("Starting NSEC3 walker for domain [" + nw.nsec.domain + "]")
	nw.out.Log(fmt.Sprintf("NS servers to walk: %v", nw.config.DomainDnsServers))

	err = nw.initNsec3Values()

	if err != nil {
		return
	}

	nw.chanDomain = make(chan *Domain, sizeChanDomain)
	dg, err := NewDomainGenerator(nw.nsec.domain, nw.nsec.saltString, nw.nsec.iterations, nw.ranges, nw.out)
	if err != nil {
		return
	}

	dg.Run(nw.chanDomain)

	for _, ns := range nw.config.DomainDnsServers {
		for i := 0; i < nw.config.cntThreadsPerNs; i++ {
			nw.cntNsWorkers++
			go nw.workerForAuthNs(ns)
		}
	}

	go nw.stats.logCounterChanges(time.Second*time.Duration(nw.config.LogCounterIntervalSec), nw.config.QuitAfterMin)

	err = nw.processHashes()

	return
}

func (nw *NSec3Walker) RunCsvUpdate() (err error) {
	update, err := NewCsvUpdate(nw.config)

	if err != nil {
		return
	}

	err = update.Run()

	if err != nil {
		return
	}

	nw.out.Logf("Added %d new domains into CSV file.", update.cntChanged)

	return
}

func (nw *NSec3Walker) RunDump() (err error) {
	dump, err := NewDump(nw.config)

	if err == nil {
		err = dump.Run()
	}

	return
}

func (nw *NSec3Walker) processHashes() (err error) {
	var startExists, endExists, isFull bool

	for hash := range nw.chanHashesFound {
		startExists, endExists, isFull, err = nw.ranges.Add(hash.Start, hash.End)

		if err != nil {
			if nw.config.QuitOnChange {
				return // The error message will be printed by the caller
			}

			// If the zone changes, and we don't quit, we can't determine if the chain is complete,
			// so will need to rely on the timeout
			nw.out.Log(err.Error())
		}

		nw.stats.gotHash(startExists, endExists)

		if !startExists {
			nw.out.Hash(hash.Start, nw.nsec)
		}

		if !endExists {
			nw.out.Hash(hash.End, nw.nsec)
		}

		if isFull {
			nw.out.Csv(hash, nw.nsec)
		}

		if nw.ranges.isFinished() {
			nw.out.Log(fmt.Sprintf("Finished with %d hashes", nw.stats.hashes.Load()))

			return
		}
	}

	return
}

func (nw *NSec3Walker) initNsec3Values() (err error) {
	var hasNsec3Param bool
	var domainDnsServers []string

	for _, ns := range nw.config.DomainDnsServers {
		nsec3param, err := getNsec3ParamResponse(nw.nsec.domain, ns)

		if err != nil {
			nw.out.Log("[" + ns + "] removed - " + err.Error())

			continue
		}

		err = nw.setNsec3Values(nsec3param.Salt, nsec3param.Iterations)
		nsec3paramMsg := "NSEC3PARAM [%s] salt [%s] and [%d] iterations"
		nw.out.Log(fmt.Sprintf(nsec3paramMsg, ns, nsec3param.Salt, nsec3param.Iterations))
		domainDnsServers = append(domainDnsServers, ns)
		hasNsec3Param = true

		if err != nil {
			return err
		}
	}

	nw.config.DomainDnsServers = domainDnsServers

	if !hasNsec3Param {
		err = fmt.Errorf("Domain [%s] is not supporting NSEC3", nw.nsec.domain)
	}

	return
}

func (nw *NSec3Walker) extractNSEC3Hashes(domain string, authNsServer string) (err error) {
	r, err := getNsResponse(domain, authNsServer)

	if err != nil {
		return
	}

	for _, rr := range r.Ns {
		if nsec, ok := rr.(*dns.NSEC); ok {
			if strings.HasPrefix(nsec.NextDomain, "\\000") {
				return errors.New(ErrorBlackLies)
			}
		}

		if nsec3, ok := rr.(*dns.NSEC3); ok {
			err = nw.setNsec3Values(nsec3.Salt, nsec3.Iterations)

			if err != nil {
				// salt or iterations changed, we need to start over
				nw.out.Fatal(err)
			}

			hashStart := strings.ToLower(strings.Split(nsec3.Header().Name, ".")[0])
			hashEnd := strings.ToLower(nsec3.NextDomain)

			if hashStart[:len(hashStart)-1] == hashEnd[:len(hashStart)-1] {
				return errors.New(ErrorWhiteLies)
			}

			nw.chanHashesFound <- Nsec3Record{hashStart, hashEnd, nsec3.TypeBitMap}
		}
	}

	return
}

func (nw *NSec3Walker) setNsec3Values(salt string, iterations uint16) (err error) {
	if nw.nsec.saltString == salt && nw.nsec.iterations == iterations {
		return
	}

	if nw.nsec.saltString != "" && nw.nsec.saltString != salt {
		return fmt.Errorf("NSEC3 salt changed from %s to %s", nw.nsec.saltString, salt)
	}

	if nw.nsec.iterations != 0 && nw.nsec.iterations != iterations {
		return fmt.Errorf("NSEC3 iterations changed from %d to %d", nw.nsec.iterations, iterations)
	}

	nw.nsec.saltString = salt
	nw.nsec.iterations = iterations

	return
}

func (nw *NSec3Walker) workerForAuthNs(ns string) {
	for domain := range nw.chanDomain {
		if nw.isDomainInRange(domain) {
			continue
		}

		time.Sleep(time.Millisecond * WaitMs)

		err := nw.extractNSEC3Hashes(domain.Domain, ns)
		nw.stats.didQuery()

		if err != nil {
			if errNoConnection(err) {
				nw.logVerbose(fmt.Sprintf("DNS server %s don't wanna talk with us, let's wait a while", ns))
				time.Sleep(time.Second * 3)
			} else if err.Error() == ErrorBlackLies {
				nw.out.Log(fmt.Sprintf("Black lies from [%s]", ns))
				break
			} else if err.Error() == ErrorWhiteLies {
				nw.out.Log(fmt.Sprintf("White lies from [%s]", ns))
				break
			} else {
				nw.out.Log(fmt.Sprintf("Error querying [%s]: %v", domain.Domain, err))
			}
		}
	}

	nw.cntNsWorkers--
	nw.out.Logf("Closing worker for [%s]", ns)

	if nw.cntNsWorkers == 0 {
		close(nw.chanHashesFound)
		nw.out.Log("There are no more NS to walk trough")
	}
}

func (nw *NSec3Walker) logVerbose(text string) {
	if nw.config.Verbose {
		nw.out.Log(text)
	}
}

func (nw *NSec3Walker) isDomainInRange(domain *Domain) (inRange bool) {
	inRange, where := nw.ranges.isHashInRange(domain.Hash)

	if inRange {
		nw.logVerbose(fmt.Sprintf("Domain in range [%s] <= %s (%s)", where, domain.Hash, domain.Domain))
	}

	return
}
