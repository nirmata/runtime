package pushsink

import (
	"testing"
	"time"
)

func TestJitteredBackoffStaysWithinTwentyPercent(t *testing.T) {
	for _, d := range []time.Duration{5 * time.Second, time.Minute} {
		for _, u := range []float64{0, 0.5, 0.999999} {
			got := jitteredBackoff(d, u)
			lo := time.Duration(float64(d) * 0.8)
			hi := time.Duration(float64(d) * 1.2)
			if got < lo || got >= hi {
				t.Errorf("jitteredBackoff(%v, %v) = %v, want in [%v, %v)", d, u, got, lo, hi)
			}
			if u == 0 && got != lo {
				t.Errorf("jitteredBackoff(%v, 0) = %v, want exactly %v", d, got, lo)
			}
		}
	}
}

func TestJitteredBackoffSpreadsDistinctDraws(t *testing.T) {
	d := time.Minute
	a := jitteredBackoff(d, 0.1)
	b := jitteredBackoff(d, 0.9)
	if a == b {
		t.Errorf("jitteredBackoff(%v, 0.1) == jitteredBackoff(%v, 0.9) == %v, want distinct waits", d, d, a)
	}
}
