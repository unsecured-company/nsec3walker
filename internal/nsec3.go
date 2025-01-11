package nsec3walker

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"strings"
)

const DnsPort = "53"

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
