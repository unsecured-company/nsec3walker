# NSEC3 Walker

A tool for collecting NSEC3 hashes from DNS zones, enabling discovery of (sub)domains.

## Install

To install into your `$GOPATH/bin` directory as `nsec3walker`.
```
go install cmd/nsec3walker.go
```
The project includes a Makefile supporting Linux, MacOS, and Windows builds. The default target is `make all`.


Available make targets:
```shell
make [all,linux,linux_amd64,linux_arm64,mac,mac_amd64,mac_arm64,windows,clean]
```

## Usage Examples

```shell
nsec3walker walk --domain cz > cz.hash 2> cz.log
nsec3walker walk --domain cz -o cz # output to cz.csv cz.log cz.hash

#get subdomains
nsec3walker walk --domain seznam.cz -o seznam_cz
```

## Command Line Options

```
nsec3walker command [flags]

Main commands:
  walk        Walk zone for a domain
  file        Process CSV & Hashcat files

Additional commands:
  debug       Show debug information for a domain
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
```

## Hash Cracking

The collected hashes can be cracked using `hashcat` with mode 8300.
The following example demonstrates cracking domains up to 10 characters long:

```
hashcat -m 8300 -a 3 --increment --custom-charset1 "?l?d-" cz.hash "?1?1?1?1?1?1?1?1?1?1"
```

## Notes
Random domains for querying are generated sequentially with a random prefix (e.g., randaaaa, randaaab, randaaac).
If you need to walk a larger zone (e.g., .cz), you can use multiple machines and merge the hashes afterward.
Unfortunately, in larger zones, changes can occur during the scan, causing issues with the chain completion check.

## TODO
- Go install from github is broken now. Clone the repository and install it locally.
- Context would be nice.
- Look for better SHA1 hashing library.


## Support
If you find NSEC3 Walker useful, feel free to support my work.  

BTC `bc1qv79sm8zp70jsqa4dpweqeg9g2lpyplfszhqzyl`  

ETH `0x7A0ac7852258578cc57635206959C848A53413a4`  

SOL `C7YKx3AUaqFGA5QafhTy7vQZVtUqiJAUP9N9nzkV2oA9`

XMR&nbsp;`85aHby9N8zRKJFvkR1sEqoAhsq3hm3XpKGNDwEozGhLkN7sfKKMLkx1KdgtxHxmJR44gHmV6MrYZPbgPLQQso4hCKMRVRmE`
