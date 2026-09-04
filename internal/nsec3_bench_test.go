package nsec3walker

import (
	"fmt"
	"testing"
)

// BenchmarkCalculateHashForDomain covers the realistic range of NSEC3
// iteration counts seen in the wild (0 is common now that high iteration
// counts are discouraged, but some zones still use up to the RFC 5155 cap).
func BenchmarkCalculateHashForDomain(b *testing.B) {
	iterations := []int{0, 1, 10, 50, 100, 500, 2500}

	for _, iter := range iterations {
		iter := iter
		b.Run(fmt.Sprintf("iterations=%d", iter), func(b *testing.B) {
			n3p, err := NewNsec3Params("example.com", "c01dc0ffee", iter)
			if err != nil {
				b.Fatalf("NewNsec3Params: %v", err)
			}

			domain := "aaaa.abcdefghij.example.com"

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				if _, err := n3p.CalculateHashForDomain(domain); err != nil {
					b.Fatalf("CalculateHashForDomain: %v", err)
				}
			}
		})
	}
}
