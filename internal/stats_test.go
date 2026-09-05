package nsec3walker

import (
	"testing"
	"time"
)

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"seconds only", 42 * time.Second, "42s"},
		{"rounds up to a minute", 59500 * time.Millisecond, "1m00s"},
		{"minutes and seconds", 3*time.Minute + 42*time.Second, "3m42s"},
		{"hours, minutes and seconds", time.Hour + 3*time.Minute + 42*time.Second, "1h03m42s"},
		{"zero", 0, "0s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatDuration(tt.d); got != tt.want {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}
