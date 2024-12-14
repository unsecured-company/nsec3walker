package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const nsMainServer88 = "8.8.8.8:53"
const nsMainServer44 = "8.8.4.4:53"
const nsMainServer11 = "1.1.1.1:53"

type NSec3Walker struct {
	GenericDnsServer []string
	AuthNsServers    []string
	Domain           string
	Salt             string
	Iterations       int
	Counter          int64

	chanDomains chan string
	chanHashes  chan string
}

func NewNSec3Walker(domain string) *NSec3Walker {
	return &NSec3Walker{
		GenericDnsServer: []string{nsMainServer88, nsMainServer44, nsMainServer11},
		AuthNsServers:    []string{},
		chanDomains:      make(chan string, 1000),
		chanHashes:       make(chan string, 1000),
		Domain:           domain,
	}
}

func main() {
	domain := os.Args[1]

	nw := NewNSec3Walker(domain)
	err := nw.Run()

	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
}

func (nw *NSec3Walker) Run() (err error) {
	nw.AuthNsServers, err = nw.getAuthNsServers()

	if err != nil {
		return
	}

	for i := 0; i < len(nw.AuthNsServers); i++ {
		go nw.domainGenerator(i)
	}

	for _, ns := range nw.AuthNsServers {
		log.Println("Starting worker for", ns)
		go nw.workerForAuthNs(ns + ":53")
	}

	go nw.logCounterChanges(time.Minute)

	for hash := range nw.chanHashes {
		fmt.Print(hash)
	}

	return
}

func (nw *NSec3Walker) domainGenerator(i int) {
	r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(i)))

	for {
		length := 15
		chars := []rune("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789")

		result := make([]rune, length)

		// start
		for i := 0; i < r.Intn(5); i++ {
			result[i] = chars[r.Intn(len(chars))]
		}

		for i := 0; i < length; i++ {
			result[i] = chars[r.Intn(len(chars))]

			nw.chanDomains <- string(result) + "." + nw.Domain
		}
	}
}

func (nw *NSec3Walker) workerForAuthNs(ns string) {
	for domain := range nw.chanDomains {
		nw.Counter++

		//log.Printf("Querying domain %s via %s\n", domain, ns)
		err := nw.extractNSEC3Hashes(domain, ns)

		if err != nil {
			log.Printf("Error querying %s: %v\n", domain, err)

			continue
		}
	}

	return
}

func (nw *NSec3Walker) getAuthNsServers() (nsAuthServers []string, err error) {
	topCount := 0
	counter := map[string]int{}
	nsResults := map[string][]string{}

	for _, server := range nw.GenericDnsServer {
		nss, err := getNameServersFromDnsServer(nw.Domain, server)

		if err != nil {
			log.Printf("Error getting NS servers from %s: %v\n", server, err)

			continue
		}

		nsResults[server] = nss
		counter[server] = len(nss)

		if len(nss) > topCount {
			topCount = len(nss)
			nsAuthServers = nss
		}
	}

	// will use later
	_ = nsResults
	_ = counter

	if len(nsAuthServers) == 0 {
		err = fmt.Errorf("no NS servers found")
	}

	return
}

func getNameServersFromDnsServer(domain, serverAddr string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	c := new(dns.Client)

	in, _, err := c.Exchange(m, serverAddr)

	if err != nil {
		return nil, err
	}

	if in.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("non-success response code: %v", in.Rcode)
	}

	var nameservers []string

	for _, ans := range in.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			nameservers = append(nameservers, ns.Ns)
		}
	}

	return nameservers, nil
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
			nw.chanHashes <- fmt.Sprintf("%s:.%s:%s:%d\n", strings.ToLower(nsec3.NextDomain), nw.Domain, nsec3.Salt, nsec3.Iterations)
		}
	}

	return
}

func (nw *NSec3Walker) logCounterChanges(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastCount int64

	for {
		<-ticker.C
		currentCount := atomic.LoadInt64(&nw.Counter)
		delta := currentCount - lastCount
		log.Printf("Total: %d, Change (last %v): %d Todo: %d\n", currentCount, interval, delta, len(nw.chanDomains))
		lastCount = currentCount
	}
}
