package nsec3walker

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"
)

const (
	DomainGeneratorMaxLength = 20
	WaitMs                   = 100
)

type NSec3Walker struct {
	config Config
	stats  Stats
	ranges *RangeIndex

	chanDomains     chan string
	chanHashesFound chan Nsec3Record
	chanHashesNew   chan string

	nsec struct {
		domain     string
		salt       string
		iterations uint16
	}
}

type Nsec3Record struct {
	Start string
	End   string
}

func NewNSec3Walker(config Config) (nsecWalker *NSec3Walker) {
	nsecWalker = &NSec3Walker{
		config:          config,
		chanDomains:     make(chan string, 1000),
		chanHashesFound: make(chan Nsec3Record, 1000),
		ranges:          NewRangeIndex(),
	}

	nsecWalker.nsec.domain = config.Domain

	return
}

func (nw *NSec3Walker) RunDebug(domain string) (err error) {
	log.Println("Showing debug data for domain: ", domain)
	log.Println("NS servers to walk: ", nw.config.DomainDnsServers)

	for _, ns := range nw.config.DomainDnsServers {
		r, err := getNsResponse(domain, ns)

		fmt.Printf("querying %s via %s\n===Err===\n%v\n\n===Response===\n%s\n\n\n", domain, ns, err, r)

		if err != nil {
			continue
		}

		for _, rr := range r.Ns {
			if nsec3, ok := rr.(*dns.NSEC3); ok {

				first := strings.Split(nsec3.Header().Name, ".")[0]
				fmt.Println(first + ";" + strings.ToLower(nsec3.NextDomain))
			}
		}
	}

	return
}

func (nw *NSec3Walker) Run() (err error) {
	log.Printf("Starting NSEC3 walker for domain [%s]\n", nw.nsec.domain)
	log.Println("NS servers to walk: ", nw.config.DomainDnsServers)

	err = nw.initNsec3Values()

	if err != nil {
		return
	}

	go nw.domainGenerator()

	for _, ns := range nw.config.DomainDnsServers {
		go nw.workerForAuthNs(ns)
	}

	go nw.stats.logCounterChanges(time.Second*time.Duration(nw.config.LogCounterIntervalSec), nw.config.QuitAfterMin)

	for hash := range nw.chanHashesFound {
		startExists, endExists, err := nw.ranges.Add(hash.Start, hash.End)

		if err != nil {
			if nw.config.StopOnChange {
				return err
			}

			log.Println(err)
		}

		if startExists {
			continue
		}

		fmt.Printf("%s:.%s:%s:%d\n", hash.Start, nw.nsec.domain, nw.nsec.salt, nw.nsec.iterations)

		if !endExists {
			fmt.Printf("%s:.%s:%s:%d\n", hash.End, nw.nsec.domain, nw.nsec.salt, nw.nsec.iterations)
		}

		nw.stats.gotHash(nw.ranges.cntChains.Load())
	}

	return
}

func (nw *NSec3Walker) initNsec3Values() (err error) {
	for _, ns := range nw.config.DomainDnsServers {
		randomDomain := fmt.Sprintf("%d-%d.%s", time.Now().UnixMilli(), rand.Uint32(), nw.nsec.domain)
		err = nw.extractNSEC3Hashes(randomDomain, ns)

		if err == nil {
			return
		}
	}

	return fmt.Errorf("could not get NSEC3 values from any of the DNS servers")
}

func (nw *NSec3Walker) domainGenerator() {
	chars := []rune("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789")
	chLen := len(chars)

	for {
		result := []rune{
			chars[rand.Intn(chLen)],
			chars[rand.Intn(chLen)],
		}

		for i := 0; i < DomainGeneratorMaxLength-2; i++ {
			result = append(result, chars[rand.Intn(chLen)])

			domain := string(result) + "." + nw.nsec.domain

			nw.chanDomains <- domain
		}
	}
}

func (nw *NSec3Walker) extractNSEC3Hashes(domain string, authNsServer string) (err error) {
	r, err := getNsResponse(domain, authNsServer)

	if err != nil {
		return
	}

	for _, rr := range r.Ns {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			err = nw.setNsec3Values(nsec3.Salt, nsec3.Iterations)

			if err != nil {
				log.Println(err)
				os.Exit(1)
				// salt or iterations changed, we need to start over
			}

			hashStart := strings.ToLower(strings.Split(nsec3.Header().Name, ".")[0])
			hashEnd := strings.ToLower(nsec3.NextDomain)

			nw.chanHashesFound <- Nsec3Record{hashStart, hashEnd}
		}
	}

	return
}

func (nw *NSec3Walker) setNsec3Values(salt string, iterations uint16) (err error) {
	if nw.nsec.salt == salt && nw.nsec.iterations == iterations {
		return
	}

	if nw.nsec.salt != "" && nw.nsec.salt != salt {
		return fmt.Errorf("NSEC3 salt changed from %s to %s\n", nw.nsec.salt, salt)
	}

	if nw.nsec.iterations != 0 && nw.nsec.iterations != iterations {
		return fmt.Errorf("NSEC3 iterations changed from %d to %d\n", nw.nsec.iterations, iterations)
	}

	nw.nsec.salt = salt
	nw.nsec.iterations = iterations

	return
}

func (nw *NSec3Walker) workerForAuthNs(ns string) {
	for domain := range nw.chanDomains {
		isInRange := nw.isDomainInRange(domain)

		if isInRange {
			continue
		}

		time.Sleep(time.Millisecond * WaitMs)

		err := nw.extractNSEC3Hashes(domain, ns)
		nw.stats.didQuery()

		if err != nil {
			if errNoConnection(err) {
				nw.logVerbose(fmt.Sprintf("DNS server %s don't wanna talk with us, let's wait a while", ns))
				time.Sleep(time.Second * 3)

				continue
			}

			log.Printf("Error querying %s: %v\n", domain, err)

			continue
		}
	}

	return
}

func (nw *NSec3Walker) logVerbose(text string) {
	if !nw.config.Verbose {
		return
	}

	log.Println(text)
}

func (nw *NSec3Walker) isDomainInRange(domain string) (inRange bool) {
	hash, err := CalculateNSEC3(domain, nw.nsec.salt, nw.nsec.iterations)

	if err != nil {
		log.Fatalf("Error calculating NSEC3 for %s: %v\n", domain, err)
	}

	inRange, where := nw.ranges.isHashInRange(hash)

	if inRange {
		nw.logVerbose(fmt.Sprintf("Domain <%s> [%s] is in range [%s]", domain, hash, where))
	}

	return
}
