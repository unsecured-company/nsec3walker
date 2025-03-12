# NSEC3 Walker

A tool for collecting NSEC3 hashes from DNS zones, enabling discovery of (sub)domains.

## Install

The project includes a Makefile supporting Linux, MacOS, and Windows builds. The default target is `make all`.

Available make targets:
```shell
make [all,linux,linux_amd64,linux_arm64,mac,mac_amd64,mac_arm64,windows,clean]
```

## Usage Examples

To scan an entire top-level domain:
```shell
nsec3walker walk --domain cz > cz.hash 2> cz.log
nsec3walker walk --domain cz -o cz
```

To scan a specific domain:
```shell
nsec3walker walk --domain seznam.cz -o seznam_cz
```

## Command Line Options

```shell
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

```shell
hashcat -m 8300 -a 3 --increment --custom-charset1 "?l?d-" cz.hash "?1?1?1?1?1?1?1?1?1?1"
```

## Support
If you find NSEC3 Walker useful, feel free to support my work.  

BTC `bc1qv79sm8zp70jsqa4dpweqeg9g2lpyplfszhqzyl`  

ETH `0x7A0ac7852258578cc57635206959C848A53413a4`  

SOL `C7YKx3AUaqFGA5QafhTy7vQZVtUqiJAUP9N9nzkV2oA9`
