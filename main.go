package main

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"log"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

const (
	DnsPort                  = "53"
	DomainGeneratorMaxLength = 20
	GenericServers           = "8.8.8.8:53,1.1.1.1:53,9.9.9.9:53"
	LogCounterIntervalSec    = 30
	QuitAfterMin             = 2
	WaitMs                   = 100
)

type Config struct {
	Domain                string
	GenericDnsServers     []string
	DomainDnsServers      []string
	Verbose               bool
	Help                  bool
	LogCounterIntervalSec uint
	QuitAfterMin          uint
}

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

func main() {
	config, err := NewConfig()

	if err != nil {
		log.Fatalf("Error - %v\n", err)
	}

	if config.Help {
		return
	}

	if config.Domain == "" {
		log.Fatalf("Provide a domain to walk.\n")
	}

	nw := NewNSec3Walker(config)
	err = nw.Run()

	if err != nil {
		log.Fatalf("Error: %v\n", err)
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

func NewConfig() (config Config, err error) {
	long := "A tool for traversing NSEC3 DNS hashes for a specified domain using its authoritative NS servers.\n"
	long += "It will run until no hashes are received for X (default 2) minutes.\nSTDOUT - hashes\nSTDERR - logging\n"

	var rootCmd = &cobra.Command{
		Use:           filepath.Base(os.Args[0]) + " [flags] domain",
		Short:         "NSEC3 Walker - Discover and traverse NSEC3 DNS hashes",
		Long:          long,
		Args:          cobra.ArbitraryArgs,
		SilenceErrors: true,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 && cmd.Flags().NFlag() == 0 {
				config.Help = true
				_ = cmd.Help()

				return
			}

			if len(args) > 0 {
				config.Domain = args[0]
			}
		},
	}

	var genericServerInput string
	var domainServerInput string

	rootCmd.Flags().StringVar(&genericServerInput, "resolver", GenericServers, "Comma-separated list of generic DNS resolvers")
	rootCmd.Flags().StringVar(&domainServerInput, "domain-ns", "", "Comma-separated list of custom authoritative NS servers for the domain")
	rootCmd.Flags().BoolVarP(&config.Verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.Flags().BoolVarP(&config.Help, "help", "h", false, "Help!")
	rootCmd.Flags().UintVar(&config.LogCounterIntervalSec, "progress", LogCounterIntervalSec, "Counters print interval in seconds")
	rootCmd.Flags().UintVar(&config.QuitAfterMin, "quit-after", QuitAfterMin, "Quit after X minutes of no new hashes")

	if err := rootCmd.Execute(); err != nil {
		return config, err
	}

	if config.Help {
		return config, nil
	}

	config.GenericDnsServers = parseDnsServers(genericServerInput)
	config.DomainDnsServers = parseDnsServers(domainServerInput)

	if len(config.DomainDnsServers) == 0 {
		config.DomainDnsServers, err = getAuthNsServers(config.Domain, config.GenericDnsServers)
	}

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

func getAuthNsServers(domain string, genericDnsServers []string) (nsAuthServers []string, err error) {
	topCount := 0
	counter := map[string]int{}
	nsResults := map[string][]string{}

	for _, server := range genericDnsServers {
		nss, err := getNameServersFromDnsServer(domain, server)

		if err != nil {
			if errNoConnection(err) {
				log.Printf("No route to %s\n", server)

				continue
			}

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
		err = fmt.Errorf("no NS servers found for domain %s", domain)
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
		return nil, fmt.Errorf("got non-success response code from DNS server: %v", in.Rcode)
	}

	var nameservers []string

	for _, ans := range in.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			nsStr := parseDnsServers(ns.Ns)[0]
			nsStr = strings.ToLower(nsStr)

			nameservers = append(nameservers, nsStr)
		}
	}

	return nameservers, nil
}

func errNoConnection(err error) bool {
	msg := err.Error()

	return strings.Contains(msg, "no route to host") || strings.Contains(msg, "i/o timeout")
}

func parseDnsServers(serversStr string) (servers []string) {
	if serversStr == "" {
		return
	}

	serversItems := strings.Split(serversStr, ",")

	for _, server := range serversItems {
		server = strings.TrimSpace(server)
		server = strings.Trim(server, ".")

		if server == "" {
			continue
		}

		if !strings.Contains(server, ":") {
			server = server + ":" + DnsPort
		}

		servers = append(servers, server)
	}

	return
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
