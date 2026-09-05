package nsec3walker

import (
	"fmt"
	"math/big"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

// statsRowFmt lays out the periodic stats line as a table: the header is
// built from this same format string so columns always line up with the
// data rows below it. EST.TOTAL~/DISC%~/MISSING~ are extrapolated from ring
// coverage so far - they can and do read 100%/0 well before the walk is
// actually done, because they don't know about ranges that exist but
// haven't yet been proven to connect to each other (see STATUS).
const statsRowFmt = "%9s %7s %11s %8s %10s %10s %8s %7s %9s %s"

type Stats struct {
	out                  *Output
	ranges               *RangeIndex
	startTime            time.Time
	hashes               atomic.Int64
	queriesWithoutResult atomic.Int64
	secondsWithoutResult atomic.Int64

	// Debug-only throughput counters, logged alongside the regular stats
	// line to see whether CPU time is going into candidate hashing vs.
	// DNS queries.
	cntCandidatesHashed atomic.Int64
	cntQueries          atomic.Int64
}

func NewStats(out *Output, ranges *RangeIndex) *Stats {
	return &Stats{
		out:       out,
		ranges:    ranges,
		startTime: time.Now(),
	}
}

// Elapsed returns how long ago this Stats (and so the walk it belongs to)
// was created.
func (stats *Stats) Elapsed() time.Duration {
	return time.Since(stats.startTime)
}

// formatDuration renders a duration as e.g. "42s", "3m42s" or "1h03m42s".
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func (stats *Stats) logCounterChanges(interval time.Duration, quitAfterMin int) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	stats.out.Log(statsHeaderRow())

	var cntHashLast, cntCandidatesLast, cntQueriesLast int64

	for {
		<-ticker.C
		cntH := stats.hashes.Load()
		deltaH := cntH - cntHashLast

		cntCandidates := stats.cntCandidatesHashed.Load()
		deltaCandidates := cntCandidates - cntCandidatesLast
		cntQ := stats.cntQueries.Load()
		deltaQ := cntQ - cntQueriesLast
		cntChains, cntEndWithoutStart := stats.ranges.DebugState()

		qWithoutResult := stats.queriesWithoutResult.Load()
		secWithoutResult := stats.secondsWithoutResult.Load()

		stats.out.Log(stats.statsDataRow(cntH, deltaH, deltaCandidates, deltaQ, interval, cntChains, cntEndWithoutStart, qWithoutResult, secWithoutResult))

		cntHashLast = cntH
		cntCandidatesLast = cntCandidates
		cntQueriesLast = cntQ
		stats.secondsWithoutResult.Add(int64(interval.Seconds()))

		if stats.secondsWithoutResult.Load() >= int64(quitAfterMin*60) {
			stats.out.Logf("No new hashes for %d seconds, quitting", secWithoutResult)
			os.Exit(0) // successful run
		}
	}
}

func statsHeaderRow() string {
	return fmt.Sprintf(statsRowFmt,
		"HASHES", "NEW", "EST.TOTAL~", "DISC%~", "MISSING~", "CAND/S", "Q/S", "CHAINS", "DANGLING", "STATUS")
}

// statsDataRow formats one line of the periodic stats table: hash count and
// delta, extrapolated zone size ("-" until enough of the ring is covered to
// estimate from), candidate-hashing/query throughput, and the incremental
// ring-completion state (chains still to be linked, dangling ends) spelled
// out in STATUS - since the estimate columns can reach 100%/0 while the
// ring is still unproven, STATUS is what actually explains what the walk is
// doing (and why CPU stays high) once that happens.
func (stats *Stats) statsDataRow(
	cntH, deltaH, deltaCandidates, deltaQ int64,
	interval time.Duration,
	cntChains int,
	cntEndWithoutStart int64,
	qWithoutResult int64,
	secWithoutResult int64,
) string {
	estimateStr, discStr, missingStr := "-", "-", "-"

	if estimatedTotal, ok := stats.ranges.EstimateTotal(cntH); ok {
		missing := new(big.Int).Sub(estimatedTotal, big.NewInt(cntH))
		if missing.Sign() < 0 {
			missing.SetInt64(0)
		}

		percent := new(big.Float).Quo(
			new(big.Float).SetInt64(cntH*100),
			new(big.Float).SetInt(estimatedTotal),
		)
		percentF, _ := percent.Float64()

		estimateStr = estimatedTotal.String()
		discStr = fmt.Sprintf("%.1f%%", percentF)
		missingStr = missing.String()
	}

	return fmt.Sprintf(statsRowFmt,
		strconv.FormatInt(cntH, 10),
		fmt.Sprintf("+%d", deltaH),
		estimateStr,
		discStr,
		missingStr,
		strconv.FormatInt(deltaCandidates/int64(interval.Seconds()), 10),
		fmt.Sprintf("%.1f", float64(deltaQ)/interval.Seconds()),
		strconv.Itoa(cntChains),
		strconv.FormatInt(cntEndWithoutStart, 10),
		ringStatus(cntChains, cntEndWithoutStart, qWithoutResult, secWithoutResult),
	)
}

// ringStatus spells out in plain words what the ring-completion bookkeeping
// (CHAINS/DANGLING) means: whether separate discovered ranges are still
// being linked together, whether it's down to proving the very last
// connection (the phase that can burn CPU for minutes with ~0 queries/s,
// since almost every guess now lands in already-covered space), or whether
// the ring has actually closed.
func ringStatus(cntChains int, cntEndWithoutStart int64, qWithoutResult int64, secWithoutResult int64) string {
	status := "-"

	switch {
	case cntChains > 1:
		status = fmt.Sprintf("linking %d ranges", cntChains)
	case cntChains == 1 && cntEndWithoutStart > 0:
		status = "verifying last connection"
	case cntChains == 1:
		status = "ring closed"
	}

	if qWithoutResult > 0 {
		status += fmt.Sprintf(" (no new hash for %dq/%ds)", qWithoutResult, secWithoutResult)
	}

	return status
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
	stats.cntQueries.Add(1)
}

func (stats *Stats) hashedCandidate() {
	stats.cntCandidatesHashed.Add(1)
}
