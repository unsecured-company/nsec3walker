package nsec3walker

import (
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const DnsPort = "53"

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
			nsStr := ParseDnsServerValue(ns.Ns)
			nsStr = strings.ToLower(nsStr)

			nameservers = append(nameservers, nsStr)
		}
	}

	return nameservers, nil
}

func ParseDnsServerValue(value string) (server string) {
	server = strings.TrimSpace(value)
	server = strings.Trim(server, ".")

	if server != "" && !strings.Contains(server, ":") {
		server = server + ":" + DnsPort
	}

	return
}

func errNoConnection(err error) bool {
	msg := err.Error()

	return strings.Contains(msg, "no route to host") || strings.Contains(msg, "i/o timeout")
}

func getNsResponse(domain string, authNsServer string) (r *dns.Msg, err error) {
	return getDnsResponse(domain, authNsServer, dns.TypeNS)
}

func getNsec3ParamResponse(domain string, authNsServer string) (r *dns.NSEC3PARAM, err error) {
	errNotExists := fmt.Errorf("NSEC3PARAM are not existing")
	rr, err := getDnsResponse(domain, authNsServer, dns.TypeNSEC3PARAM)

	if err != nil {
		return
	}

	if len(rr.Answer) == 0 {
		return nil, errNotExists
	}

	nsec3param, ok := rr.Answer[0].(*dns.NSEC3PARAM)

	if !ok {
		return nil, errNotExists
	}

	if nsec3param.Hash != dns.SHA1 {
		return nil, fmt.Errorf("NSEC3 hash is not SHA1")
	}

	return nsec3param, nil
}

func getDnsResponse(domain string, authNsServer string, dnsType uint16) (r *dns.Msg, err error) {
	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dnsType)
	m.SetEdns0(4096, true)
	c.DialTimeout = time.Second * 5
	c.ReadTimeout = time.Second * 10
	c.WriteTimeout = time.Second * 5

	r, _, err = c.Exchange(&m, authNsServer)

	return
}

func CalculateNSEC3(domain string, salt []byte, iterations uint16) (string, error) {
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

// domainToWire converts a domain name to its wire format (canonical form) as specified in RFC 4034 Section 6.2
func domainToWire(domain string) ([]byte, error) {
	if domain == "" {
		return nil, fmt.Errorf("empty domain name")
	}

	domain = strings.TrimSuffix(domain, ".")
	labels := strings.Split(domain, ".")

	// Calculate required size for wire format
	size := 0
	for _, label := range labels {
		size += len(label) + 1 // +1 for length byte
	}
	size++ // +1 for root label (zero byte)

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
