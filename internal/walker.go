package nsec3walker

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"math"
	"math/rand"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const (
	DomainGeneratorMaxLength = 20
	WaitMs                   = 100
)

type Stats struct {
	queries              atomic.Int64
	hashes               atomic.Int64
	queriesWithoutResult atomic.Int64
	secondsWithoutResult atomic.Int64
}

type NSec3Walker struct {
	config Config
	stats  Stats
	memory map[string]int

	chanDomains     chan string
	chanHashesFound chan string
	chanHashesNew   chan string

	nsec struct {
		domain     string
		salt       string
		iterations uint16
	}
}

func NewNSec3Walker(config Config) (nsecWalker *NSec3Walker) {
	nsecWalker = &NSec3Walker{
		config:          config,
		chanDomains:     make(chan string, 1000),
		chanHashesFound: make(chan string, 1000),
		memory:          make(map[string]int),
	}

	nsecWalker.nsec.domain = config.Domain

	return
}

func (nw *NSec3Walker) Run() (err error) {
	log.Printf("Starting NSEC3 walker for domain [%s]\n", nw.nsec.domain)
	log.Println("NS servers to walk: ", nw.config.DomainDnsServers)

	go nw.domainGenerator()

	for _, ns := range nw.config.DomainDnsServers {
		go nw.workerForAuthNs(ns)
	}

	go nw.stats.logCounterChanges(time.Second*time.Duration(nw.config.LogCounterIntervalSec), nw.config.QuitAfterMin)

	for hash := range nw.chanHashesFound {
		if nw.checkMemory(hash) {
			continue
		}

		nw.stats.gotHash()

		fmt.Printf("%s:.%s:%s:%d\n", hash, nw.nsec.domain, nw.nsec.salt, nw.nsec.iterations)
	}

	return
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

			nw.chanDomains <- string(result) + "." + nw.nsec.domain
		}
	}
}

func (nw *NSec3Walker) extractNSEC3Hashes(domain string, authNsServer string) (err error) {
	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.SetEdns0(4096, true)
	c.DialTimeout = time.Second * 3
	c.ReadTimeout = time.Second * 10
	c.WriteTimeout = time.Second * 3

	r, _, err := c.Exchange(&m, authNsServer)

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

			start := strings.Split(nsec3.Header().Name, ".")[0]
			end := strings.ToLower(nsec3.NextDomain)

			nw.chanHashesFound <- start
			nw.chanHashesFound <- end
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

func (nw *NSec3Walker) checkMemory(hash string) (exists bool) {
	_, exists = nw.memory[hash]

	if !exists {
		nw.memory[hash] = 0
	}

	nw.memory[hash]++

	return
}

func (nw *NSec3Walker) workerForAuthNs(ns string) {
	for domain := range nw.chanDomains {
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

func (stats *Stats) logCounterChanges(interval time.Duration, quitAfterMin uint) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var cntQueryLast int64
	var cntHashLast int64

	for {
		<-ticker.C
		cntQuery := stats.queries.Load()
		cntHash := stats.hashes.Load()
		cntQ := atomic.LoadInt64(&cntQuery)
		cntH := atomic.LoadInt64(&cntHash)
		deltaQ := cntQ - cntQueryLast
		deltaH := cntH - cntHashLast
		ratioTotal := calculateRatio(cntH, cntQ)
		ratioDelta := calculateRatio(deltaH, deltaQ)

		msg := "In the last %v: Queries total/change %d/%d | Hashes total/change: %d/%d | Ratio total/change %d%%/%d%% | Without answer: %d , seconds %d\n"
		log.Printf(msg, interval, cntQ, deltaQ, cntH, deltaH, ratioTotal, ratioDelta, stats.queriesWithoutResult.Load(), stats.secondsWithoutResult.Load())

		cntQueryLast = cntQ
		cntHashLast = cntH
		stats.secondsWithoutResult.Add(int64(interval.Seconds()))

		secWithoutResult := stats.secondsWithoutResult.Load()

		if secWithoutResult >= int64(quitAfterMin*60) {
			log.Printf("No new hashes for %d seconds, quitting\n", secWithoutResult)
			os.Exit(0)
		}
	}
}

func (stats *Stats) gotHash() {
	stats.hashes.Add(1)
	stats.queriesWithoutResult.Store(0)
	stats.secondsWithoutResult.Store(0)
}

func (stats *Stats) didQuery() {
	stats.queries.Add(1)
	stats.queriesWithoutResult.Add(1)
}

func calculateRatio(numerator, denominator int64) int {
	if denominator == 0 {
		return 0
	}

	ratio := int(math.Round((float64(numerator) / float64(denominator)) * 100))

	// Sometimes goes over 100% - great work, comrades!
	if ratio > 100 {
		return 100
	}

	return ratio
}
