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
	fullDom := n3p.GetFullDomain(domainPrefix)

	return n3p.CalculateHashForDomain(fullDom)
}

func (n3p Nsec3Params) CalculateHashForDomain(domainFull string) (hash string, err error) {
	// Convert domain name to wire format (canonical form)
	wire, err := domainToWire(domainFull)
	if err != nil {
		return "", fmt.Errorf("invalid domain name: %w", err)
	}

	// Initial hash
	sum := sha1.Sum(append(wire, n3p.saltBytes...))

	// Perform additional iterations, reusing a single (hash || salt) buffer
	// instead of allocating a new hash.Hash and result slice every round.
	if n3p.iterations > 0 {
		buf := make([]byte, sha1.Size+len(n3p.saltBytes))
		copy(buf[sha1.Size:], n3p.saltBytes)

		for i := uint16(0); i < n3p.iterations; i++ {
			copy(buf[:sha1.Size], sum[:])
			sum = sha1.Sum(buf)
		}
	}

	// Encode the final hash using base32hex (with padding removed)
	encoded := base32.HexEncoding.EncodeToString(sum[:])
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
			nsStr := prepareDnsServerAddress(ns.Ns)

			nameservers = append(nameservers, nsStr)
		}
	}

	return nameservers, nil
}

func prepareDnsServerAddress(value string) (server string) {
	server = strings.ToLower(strings.Trim(strings.TrimSpace(value), "."))

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

// domainToWire converts a domain name to its wire format (canonical form) as specified in RFC 4034 Section 6.2
func domainToWire(domain string) (domainB []byte, err error) {
	if domain == "" {
		return
	}

	domain = strings.TrimSuffix(domain, ".")

	// Every label contributes its bytes plus one length-prefix byte, and
	// the dots separating them are dropped, so the wire form is always
	// exactly len(domain)+1 bytes plus the root's trailing zero byte -
	// avoids re-deriving the size from a strings.Split allocation.
	wire := make([]byte, 0, len(domain)+2)
	rest := domain

	for {
		i := strings.IndexByte(rest, '.')
		var label string

		if i < 0 {
			label = rest
			rest = ""
		} else {
			label = rest[:i]
			rest = rest[i+1:]
		}

		if len(label) == 0 {
			return nil, fmt.Errorf("empty label in domain name")
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("label too long: %s", label)
		}

		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)

		if i < 0 {
			break
		}
	}

	wire = append(wire, 0) // Add root label

	return wire, nil
}
