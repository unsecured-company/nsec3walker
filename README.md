# NSEC3 Walker

A tool for collecting NSEC3 hashes from DNS zones, enabling discovery of (sub)domains.

## Install

To install into your `$GOPATH/bin` directory as `nsec3walker`.
```
go install .
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
nsec3walker walk --domain paypal.com -o paypal_com

#output to a specific directory (directories will be created if they don't exist)
nsec3walker walk --domain example.com -o /data/dns/scans/example_com
```

## Command Line Options

```
nsec3walker command [flags]

Main commands:
  walk        Walk zone for a domain
  file        Process CSV & Hashcat files
  crack       Simple build in cracking of hashes using a wordlist

Additional commands:
  debug       Show debug information for a domain
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
```

## Output files
When using `-o`, three files will be created:  
`.log` with log output, which is also on stderr  
`.hash` with hashes formated for Hashcat, which is otherwise on stdout  
`.csv` with additional data.  

#### CSV file
```
i7jb4ch51v6euviceg2qn00tsol2uj70 , i7jd5de5id4on4ktjrfi3cqt683mc88p , cz ,    5a992f48cfb97692, 0 ,          vitezslav-lindovsky.cz , NS|DS|RRSIG
^hash of the domain(label)         ^hash of the next domain(label)    ^top domain        salt^  ^iterations  ^plaintext               ^available dns record types, not exhaustive
```

## Hash Cracking

The collected hashes can be cracked using `hashcat` with mode `8300`.

```
hashcat -m 8300 -a 3 --increment --custom-charset1 "?l?d-" nsec.hash "?1?1?1?1?1?1?1?1?1?1"
```

For a wordlist, a good start is `Discovery/DNS/combined_subdomains.txt` from [SecList](https://github.com/danielmiessler/SecLists)

```
hashcat -m 8300 -a 0 nsec.hash /usr/share/wordlist/seclist/Discovery/DNS/ALL
```

If you don't have hashcat, you can use the build in cracking, which is of course slow.  
That operates with the `.csv` file, and it will update the file in place.
```
nsec3walker crack --file-csv nsec.csv --file-wordlist wordlist.txt
```

## Typical workflow
We can have a folder per domain, and collect data into common named file `nsec.*`
```
nsec3walker walk --domain paypal.com -o nsec
```

After cracking the hashes, you can update the `.csv` using Hashcat's Pot file.

```
nsec3walker file --file-hashcat ~/.local/share/hashcat/hashcat.potfile --file-csv nsec.csv --update-csv
```

We can then create wordlist. This is useful for new data, when the salt/iterations changes, and to get few more domains,
by adding numbers to the words. The build in cracking feature is great exactly for that.

```
nsec3walker file --file-csv nsec.csv --dump-wordlist >> wordlist.txt
sort -u wordlist.txt > wordlist_new.txt
mv wordlist_new.txt wordlist.txt
```

And finally, we can get list of domains.

```
nsec3walker file --file-csv nsec.csv --dump-domains >> domains.txt
sort -u domains.txt > domains_new.txt
mv domains_new.txt domains.txt
```

## Notes
Random domains for querying are generated sequentially with a random prefix (e.g., randaaaa, randaaab, randaaac).  
If you need to walk a larger zone (e.g., .cz), you can use multiple machines and merge the hashes afterward.  
Unfortunately, in larger zones, changes can occur during the scan, causing issues with the chain completion check.  

## TODO
- Go install from GitHub is broken now. Clone the repository and install it locally using `go install .`
- Context would be nice.
- Look for better SHA1 hashing library.

## Support
If you find NSEC3 Walker useful, feel free to support my work.  

BTC `bc1qv79sm8zp70jsqa4dpweqeg9g2lpyplfszhqzyl`  

ETH `0x7A0ac7852258578cc57635206959C848A53413a4`  

SOL `C7YKx3AUaqFGA5QafhTy7vQZVtUqiJAUP9N9nzkV2oA9`

XMR&nbsp;`85aHby9N8zRKJFvkR1sEqoAhsq3hm3XpKGNDwEozGhLkN7sfKKMLkx1KdgtxHxmJR44gHmV6MrYZPbgPLQQso4hCKMRVRmE`
