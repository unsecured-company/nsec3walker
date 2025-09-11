package nsec3walker

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

type Cracking struct {
	cnf          *Config
	out          *Output
	fileWordlist *os.File
	csv          *Csv
	chanWords    chan string
	chanCsv      chan CsvItem
	wgFile       sync.WaitGroup
	hashes       map[string]map[string]string
	nsec3params  map[string]Nsec3Params
	wgCracker    sync.WaitGroup
	cracked      *Cracked
}

func NewCracking(cnf *Config, out *Output) (c *Cracking) {
	c = &Cracking{
		cnf:         cnf,
		out:         out,
		chanWords:   make(chan string, 1000),
		chanCsv:     make(chan CsvItem, 1000),
		hashes:      make(map[string]map[string]string),
		nsec3params: make(map[string]Nsec3Params),
		cracked:     NewCracked(),
	}

	return
}

func (c *Cracking) Run() (err error) {
	hasFile := c.cnf.FileWordlist != ""
	hasDomain := c.cnf.Domain != ""

	if hasFile {
		return c.runWordlist()
	} else if hasDomain {
		return c.runSingle()
	} else {
		return fmt.Errorf("either --file-wordlist or --domain must be specified")
	}
}

func (c *Cracking) runWordlist() (err error) {
	err = c.prepareCsv()
	if err != nil {
		return
	}

	c.fileWordlist, err = os.Open(c.cnf.FileWordlist)
	if err != nil {
		return
	}

	c.wgFile.Go(func() {
		err = FileToChan(c.fileWordlist, c.chanWords, true)
		if err != nil {
			c.out.Log(err.Error())
		}
	})

	c.wgCracker.Add(3)
	go c.runCracker()
	go c.runCracker()
	go c.runCracker()

	c.wgCracker.Wait()

	c.out.Logf("Updating CSV with %d cracked hashes.", c.cracked.Count())
	update := NewCsvUpdateForData(c.cnf, c.csv, c.cracked)
	err = update.Run()
	if err != nil {
		return
	}

	c.out.Logf("Added %d new domains into CSV file.", update.cntChanged)

	return
}

func (c *Cracking) prepareCsv() (err error) {
	c.csv, err = NewCsv(c.cnf.FileCsv, c.cnf.Output)
	if err != nil {
		return
	}

	go func() {
		errRead := c.csv.ReadToChan(c.chanCsv, true)
		if errRead != nil {
			c.out.Log(errRead.Error())
		}
	}()

	var n3p Nsec3Params
	for csvItem := range c.chanCsv {
		n3p, err = NewNsec3Params(csvItem.Domain, csvItem.Salt, csvItem.Iterations)
		if err != nil {
			return
		}

		if c.hashes[n3p.key] == nil {
			c.hashes[n3p.key] = make(map[string]string)
			c.nsec3params[n3p.key] = n3p
		}

		c.hashes[n3p.key][csvItem.Hash] = ""
	}

	return
}

func (c *Cracking) crack(word string, n3p Nsec3Params) (err error) {
	hash, err := n3p.CalculateHashForPrefix(word)
	if err != nil {
		return
	}

	printHashcatFormat(hash, word, n3p.domain, n3p)

	return
}

func printHashcatFormat(hash string, domPrefix string, domSuffix string, np Nsec3Params) {
	domSuffix = strings.TrimPrefix(domSuffix, ".")

	fmt.Printf("%s:.%s:%s:%d:%s\n", hash, domSuffix, np.saltString, np.iterations, domPrefix)
}

func (c *Cracking) runSingle() (err error) {
	n3p, err := NewNsec3Params(c.cnf.Domain, c.cnf.Salt, c.cnf.Iterations)
	if err != nil {
		return
	}

	msg := "Get hash for domain [%s] with salt [%s] having [%d] iterations.\n"
	c.out.Logf(msg, n3p.domain, n3p.saltString, n3p.iterations)
	hash, err := n3p.CalculateHashForPrefix(n3p.domain)
	if err != nil {
		return
	}

	parts := strings.Split(n3p.domain, ".")
	domPrefix := parts[0]
	domSuffix := strings.TrimPrefix(n3p.domain, domPrefix)

	printHashcatFormat(hash, "", n3p.domain, n3p)
	printHashcatFormat(hash, domPrefix, domSuffix, n3p)

	return
}

func (c *Cracking) runCracker() {
	for word := range c.chanWords {
		for _, n3p := range c.nsec3params {
			domain := strings.TrimLeft(word+"."+n3p.domain, ".")
			hash, err := n3p.CalculateHashForPrefix(domain)
			if err != nil {
				return
			}

			plaintext, ok := c.hashes[n3p.key][hash]
			if ok == false || plaintext == word {
				continue
			}

			c.cracked.Add(n3p, hash, word)
		}
	}

	c.wgCracker.Done()
}
