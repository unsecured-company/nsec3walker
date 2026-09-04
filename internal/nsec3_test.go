package nsec3walker

import "testing"

// Expected hashes were generated with github.com/miekg/dns's independent
// HashName implementation of RFC 5155, not copied from memory, and the first
// three vectors reproduce RFC 5155 Appendix A's example zone
// (example./aabbccdd/12 iterations).
func TestCalculateHashForDomain(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		salt       string
		iterations int
		want       string
	}{
		{"rfc5155 apex", "example.", "aabbccdd", 12, "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"},
		{"rfc5155 a.example", "a.example.", "aabbccdd", 12, "35mthgpgcu1qg68fab165klnsnk3dpvl"},
		{"rfc5155 ai.example", "ai.example.", "aabbccdd", 12, "gjeqe526plbf1g8mklp59enfd789njgi"},
		{"zero iterations", "example.com.", "c01dc0ffee", 0, "7mckp4i3r1srn11savesh8c0enldlaoc"},
		{"one iteration", "example.com.", "c01dc0ffee", 1, "gap5lncbuibbqokb05m16t8vfl43l2cc"},
		{"ten iterations", "example.com.", "c01dc0ffee", 10, "0t83jhf6oljp1dd2fsbb9n1ig4t45igv"},
		{"hundred iterations", "example.com.", "c01dc0ffee", 100, "6ov1ebqlamv9mkq934livfdp05ue8uit"},
		{"max rfc5155 iterations", "aaaa.abcdefghij.example.com.", "c01dc0ffee", 2500, "cljbaln9r72dm01dfoeferpath1eb3n5"},
		{"empty salt", "example.com.", "", 0, "onib9mgub9h0rml3cdf5bgrj59dkjhvk"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n3p, err := NewNsec3Params(tt.domain, tt.salt, tt.iterations)
			if err != nil {
				t.Fatalf("NewNsec3Params: %v", err)
			}

			got, err := n3p.CalculateHashForDomain(tt.domain)
			if err != nil {
				t.Fatalf("CalculateHashForDomain: %v", err)
			}

			if got != tt.want {
				t.Errorf("CalculateHashForDomain(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}
