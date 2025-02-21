package nsec3walker

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
)

type Dump struct {
	HashCat    *HashCat
	Csv        *Csv
	out        *Output
	cnf        Config
	cntChanged int
}

func NewDump(config Config, out *Output) (dump *Dump, err error) {
	hashCat, err := NewHashCat(config.FileHashcat, out, config)
	if err != nil {
		return
	}

	csv, err := NewCsv(config.FileCsv, out)

	if err != nil {
		return
	}

	dump = &Dump{
		HashCat: hashCat,
		Csv:     csv,
		out:     out,
		cnf:     config,
	}

	return
}

func (d *Dump) Run() (err error) {
	err = d.Csv.StartNew()

	if err != nil {
		return
	}

	chanCsvItem := make(chan CsvItem, 10)
	go d.csvToChan(chanCsvItem)

	for csvItem := range chanCsvItem {
		key := getHashcatMapKey(csvItem.Domain, csvItem.Salt, csvItem.Iterations)
		_, ok := d.HashCat.Domains[key]

		if ok {
			plaintext, ok := d.HashCat.Domains[key][csvItem.Hash]

			if ok && plaintext != csvItem.Plaintext {
				csvItem.Plaintext = plaintext
				d.cntChanged++
			}
		}

		err = d.Csv.FileTemp.Insert(csvItem)

		if err != nil {
			return
		}
	}

	err = d.Csv.Replace()

	return
}

func (d *Dump) csvToChan(chanCsvItem chan CsvItem) {
	err := d.Csv.ReadToChan(chanCsvItem)
	close(chanCsvItem)

	if err != nil {
		d.out.Log(err.Error())
	}
}

func (d *Dump) resolveDNS(domain, recordType string) {
	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.StringToType[recordType])
	response, _, err := client.Exchange(msg, "8.8.8.8:53") // Using Google's resolver

	if err != nil {
		log.Printf("Failed to resolve %s (%s): %v", domain, recordType, err)
		return
	}

	for _, ans := range response.Answer {
		fmt.Println(ans)
	}
}
