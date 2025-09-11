package nsec3walker

import (
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const DnsPort = "53"

type Nsec3Params struct {
	domain     string
	saltString string
	saltBytes  []byte
	iterations uint16
	key        string
}

func NewNsec3Params(domain string, salt string, iterations int) (n3p Nsec3Params, err error) {
	n3p = Nsec3Params{
		domain:     strings.TrimLeft(domain, "."),
		saltString: salt,
		iterations: uint16(iterations),
	}

	n3p.key = fmt.Sprintf("%s|%s|%v", n3p.domain, n3p.saltString, n3p.iterations)
	n3p.saltBytes, err = hex.DecodeString(salt)

	return
}

func (n3p Nsec3Params) GetFullDomain(domainPrefix string) string {
	return strings.TrimLeft(domainPrefix+"."+n3p.domain, ".")
}

func (n3p Nsec3Params) CalculateHashForPrefix(domainPrefix string) (hash string, err error) {
	// Convert domain name to wire format (canonical form)
	wire, err := domainToWire(n3p.GetFullDomain(domainPrefix))
	if err != nil {
		return "", fmt.Errorf("invalid domain name: %w", err)
	}

	// Initial hash
	hashB := calculateHashSha1(wire, n3p.saltBytes)

	// Perform additional iterations
	for i := uint16(0); i < n3p.iterations; i++ {
		hashB = calculateHashSha1(hashB, n3p.saltBytes)
	}

	// Encode the final hash using base32hex (with padding removed)
	encoded := base32.HexEncoding.EncodeToString(hashB)
	encoded = strings.TrimRight(encoded, "=")

	return strings.ToLower(encoded), nil
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

// calculateHash performs a single round of SHA-1 hashing
func calculateHashSha1(data, salt []byte) []byte {
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
