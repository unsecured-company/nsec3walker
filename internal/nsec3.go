package nsec3walker

import (
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"strings"
	"time"
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

func getNsResponse(domain string, authNsServer string) (r *dns.Msg, err error) {
	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.SetEdns0(4096, true)
	c.DialTimeout = time.Second * 5
	c.ReadTimeout = time.Second * 10
	c.WriteTimeout = time.Second * 5

	r, _, err = c.Exchange(&m, authNsServer)

	return
}

func CalculateNSEC3(domain string, saltHex string, iterations uint16) (string, error) {
	// Convert salt from hex to bytes
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return "", fmt.Errorf("invalid salt format: %w", err)
	}

	// Convert domain name to wire format (canonical form)
	wire, err := domainToWire(domain)
	if err != nil {
		return "", fmt.Errorf("invalid domain name: %w", err)
	}

	// Initial hash
	hash := calculateHash(wire, salt)

	// Perform additional iterations
	for i := uint16(0); i < iterations; i++ {
		hash = calculateHash(hash, salt)
	}

	// Encode the final hash using base32hex (with padding removed)
	encoded := base32.HexEncoding.EncodeToString(hash)
	encoded = strings.TrimRight(encoded, "=")
	return strings.ToLower(encoded), nil
}

// calculateHash performs a single round of SHA-1 hashing
func calculateHash(data, salt []byte) []byte {
	h := sha1.New()
	h.Write(data)
	h.Write(salt)
	return h.Sum(nil)
}

// domainToWire converts a domain name to its wire format (canonical form)
// as specified in RFC 4034 Section 6.2
func domainToWire(domain string) ([]byte, error) {
	if domain == "" {
		return nil, fmt.Errorf("empty domain name")
	}

	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")

	// Split domain into labels
	labels := strings.Split(domain, ".")

	// Calculate required size for wire format
	size := 0
	for _, label := range labels {
		size += len(label) + 1 // +1 for length byte
	}
	size++ // +1 for root label (zero byte)

	// Create wire format
	wire := make([]byte, 0, size)
	for _, label := range labels {
		if len(label) > 63 {
			return nil, fmt.Errorf("label too long: %s", label)
		}
		if len(label) == 0 {
			return nil, fmt.Errorf("empty label in domain name")
		}
		wire = append(wire, byte(len(label)))
		wire = append(wire, []byte(label)...)
	}
	wire = append(wire, 0) // Add root label

	return wire, nil
}
