# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`nsec3walker` is a Go CLI for "walking" NSEC3-enabled DNS zones to discover (sub)domains via DNSSEC's authenticated denial-of-existence mechanism. It generates candidate domain hashes, queries authoritative nameservers, chains the returned NSEC3 ranges until the ring is complete, and outputs hashes (for Hashcat), a CSV of metadata, and logs. It also includes a built-in (slow) hash cracker as an alternative to Hashcat.

## Build/Test Commands

```bash
go build -o bin/nsec3walker .   # local build
go install .                     # install into $GOPATH/bin

make [all,linux,linux_amd64,linux_arm64,mac,mac_amd64,mac_arm64,windows,clean,test,race,bench]

go test ./...                                   # run all tests, quiet on pass (same as `make test`)
go test -run TestHashTree_ClosestBefore ./internal   # run a single test
go test -race ./...                             # concurrency-sensitive code (walker.go, range.go) - run before considering such changes done; same as `make race`
go test -run '^$' -bench . -benchmem ./internal/...  # run all benchmarks, no tests; same as `make bench`

go fmt ./...
go vet ./...
```

Tests currently live in `internal/range_test.go` (covers `HashTree`/`RangeIndex`).

## Architecture

Everything lives in the single `internal` package (module `github.com/unsecured-company/nsec3walker`); `main.go` just wires `Config` -> `NSec3Walker` and dispatches on `config.Action`.

### Command flow (`internal/config.go`)
Cobra defines four commands (`walk`, `file`, `crack`, `debug`), each populating a shared `Config` struct and setting `Config.Action` to one of the `Action*` constants. `main.go` switches on `Action` and calls the matching `NSec3Walker.Run*` method. `file` is really two sub-actions (`--update-csv` vs `--dump-domains`/`--dump-wordlist`) chosen via `PostRunE` validation.

### The walk pipeline (`internal/walker.go`)
`NSec3Walker.RunWalk` is the core flow:
1. `processAuthNsServers` resolves the domain's authoritative nameservers (or uses `--nameservers`).
2. `initNsec3Values` queries NSEC3PARAM from each NS to learn salt/iterations (must be SHA1 and consistent across all servers — a mismatch is fatal, since the whole hash space depends on it).
3. A `DomainGenerator` (`internal/generator.go`) is started: one goroutine sequentially generates candidate domains (`aaaa.<random-prefix>.<domain>`, incrementing like an odometer over `abcdefghijklmnopqrstuvwxyz0123456789`), fanned out to `runtime.NumCPU()` hash workers that compute each candidate's NSEC3 hash and skip anything already known to be covered by a discovered range.
4. Per-nameserver worker goroutines (`cntThreadsPerNs` each) pull generated domains, skip ones already in a known range, and query NS for NSEC/NSEC3 records (`extractNSEC3Hashes`), detecting NSEC (non-NSEC3) "black lies" and zero-width "white lies" as attacker/misconfiguration signals.
5. Discovered `(hashStart, hashEnd)` ranges feed `processHashes`, which inserts them into a `RangeIndex` (`internal/range.go`) — a red-black-tree-backed structure tracking the NSEC3 hash ring. The walk is done when `RangeIndex.isFinished()` reports the ring is fully chained (every start matches a prior end, and it wraps around).
6. `Output` (`internal/output.go`) streams newly-seen hashes to `.hash`, completed ranges to `.csv`, and progress/errors to `.log`/stderr. `Stats` (`internal/stats.go`) tracks counters and can auto-quit after `N` minutes without new hashes.

Because NSEC3 hashing is expensive and zones can be huge, correctness of `RangeIndex` (ring completion detection, closest-range lookup) is the trickiest part of this codebase — see `internal/range_test.go` for its expected behavior before changing it.

### Hashing (`internal/nsec3.go`)
`Nsec3Params.CalculateHashForDomain` implements RFC 5155 NSEC3 hashing directly (wire-format domain encoding -> iterated SHA-1 with salt -> base32hex, no padding, lowercased) rather than depending on `miekg/dns`'s hasher. `domainToWire` is the canonical wire-format encoder this depends on.

### CSV / cracking / hashcat interop (`internal/csv.go`, `cracking.go`, `cracked.go`, `hashcat.go`, `csv_update.go`, `dump.go`)
- `Csv` reads/validates/rewrites the `.csv` file (7 semicolon-free comma-separated fields: hash, next-hash, domain, salt, iterations, plaintext, DNS record types joined by `|`).
- `Cracked` is a shared in-memory result set (`"domain|salt|iterations"` -> `hash -> plaintext`), populated either from a Hashcat potfile (`HashCat.load`) or from the built-in cracker (`Cracking.runCracker`, checked against a wordlist).
- `CsvUpdate` merges newly-cracked plaintexts back into the CSV by writing a `.tmp` file and atomically replacing the original (`Csv.Replace` refuses to replace if the temp file is smaller — a corruption guard).
- `Dump` implements `file --dump-domains`/`--dump-wordlist`, extracting plaintext domains from CSV and/or Hashcat potfiles, optionally stripping the base domain suffix to produce wordlist fragments.

## Testing conventions

- New or changed behavior needs a test alongside it (`internal/*_test.go`); run the suite (`go test ./...`) before calling a task done, not just `go build`.
- Much of this codebase is concurrent (`DomainGenerator` fan-out, per-NS worker goroutines in `walker.go`, the mutexes in `range.go`) — when touching that code, verify with `make race` (`go test -race ./...`) too.
- When a change is meant to affect performance (hashing, `RangeIndex` lookups/inserts, hot loops in the walk pipeline), add or update a `Benchmark*` alongside the test and report before/after numbers via `go test -run '^$' -bench . -benchmem ./internal/...`. See `internal/range_test.go` for existing examples (`BenchmarkRangeIndex_Add`, `BenchmarkRangeIndex_isHashInRange` and its `_Miss` variant, `BenchmarkRangeIndex_Concurrent`).

