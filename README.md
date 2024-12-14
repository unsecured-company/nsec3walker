# NSEC3 Walker

NSEC3 walker to get hashes. These will be later cracked to get list of existing (sub)domains.

Quick & Dirty **WiP** PoC, LoL.

## Example usage

```
go run main.go cz          > cz.hashes        2> cz.log
go run main.go seznam.cz   > seznam.cz.hashes 2> seznam.cz.log
```

- STDOUT will contain NSEC3 hashes.
- STDER will contain logs.

## Cracking

Use hashcat with mode 8300.

```
hashcat -m 8300 -a 3 cz.hashes
```
