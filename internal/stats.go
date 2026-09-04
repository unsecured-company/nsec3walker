package nsec3walker

import (
	"fmt"
	"math/big"
	"os"
	"sync/atomic"
	"time"
)

type Stats struct {
	out                  *Output
	ranges               *RangeIndex
	hashes               atomic.Int64
	queriesWithoutResult atomic.Int64
	secondsWithoutResult atomic.Int64
}

func NewStats(out *Output, ranges *RangeIndex) *Stats {
	return &Stats{
		out:    out,
		ranges: ranges,
	}
}

func (stats *Stats) logCounterChanges(interval time.Duration, quitAfterMin int) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var cntHashLast int64

	for {
		<-ticker.C
		cntH := stats.hashes.Load()
		deltaH := cntH - cntHashLast

		qWithoutResult := stats.queriesWithoutResult.Load()
		secWithoutResult := stats.secondsWithoutResult.Load()

		msg := fmt.Sprintf("Hashes: %d (+%d in last %v)", cntH, deltaH, interval)
		msg += stats.estimateMsg(cntH)

		if qWithoutResult > 0 {
			msg += fmt.Sprintf(" | No new hash for %d queries / %ds", qWithoutResult, secWithoutResult)
		}

		stats.out.Log(msg)

		cntHashLast = cntH
		stats.secondsWithoutResult.Add(int64(interval.Seconds()))

		if stats.secondsWithoutResult.Load() >= int64(quitAfterMin*60) {
			stats.out.Logf("No new hashes for %d seconds, quitting", secWithoutResult)
			os.Exit(0) // successful run
		}
	}
}

// estimateMsg formats the predicted zone size, e.g. " | Estimated zone size:
// ~1234 (42.0% discovered, ~700 missing)". It returns "" until enough of the
// ring has been covered to extrapolate from.
func (stats *Stats) estimateMsg(discovered int64) string {
	estimatedTotal, ok := stats.ranges.EstimateTotal(discovered)
	if !ok {
		return ""
	}

	missing := new(big.Int).Sub(estimatedTotal, big.NewInt(discovered))
	if missing.Sign() < 0 {
		missing.SetInt64(0)
	}

	percent := new(big.Float).Quo(
		new(big.Float).SetInt64(discovered*100),
		new(big.Float).SetInt(estimatedTotal),
	)
	percentF, _ := percent.Float64()

	return fmt.Sprintf(" | Estimated zone size: ~%s (%.1f%% discovered, ~%s missing)", estimatedTotal, percentF, missing)
}

func (stats *Stats) gotHash(startExists bool, endExists bool) {
	add := 0

	if !startExists {
		add++
	}

	if !endExists {
		add++
	}

	stats.hashes.Add(int64(add))
	stats.queriesWithoutResult.Store(0)
	stats.secondsWithoutResult.Store(0)
}

func (stats *Stats) didQuery() {
	stats.queriesWithoutResult.Add(1)
}
