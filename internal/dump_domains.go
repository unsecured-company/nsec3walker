package nsec3walker

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
)

type DumpDomains struct {
	cnf     *Config
	HashCat *HashCat
	Csv     *Csv
}

func NewDumpDomains(config *Config) (dump *DumpDomains, err error) {
	dump = &DumpDomains{
		cnf:     config,
		Csv:     nil,
		HashCat: nil,
	}

	if config.FileHashcat != "" {
		dump.HashCat, err = NewHashCat(config.FileHashcat, config)

		if err != nil {
			return
		}
	}

	if config.FileCsv != "" {
		dump.Csv, err = NewCsv(config.FileCsv, config.Output)

		if err != nil {
			return
		}
	}

	return
}

func (d *DumpDomains) Run() (err error) {
	if d.Csv != nil {
		d.dumpCsv()
	}

	if d.HashCat != nil {
		d.dumpHashCat()
	}

	return
}

func (d *DumpDomains) dumpCsv() {
	chanCsvItem := make(chan CsvItem, 10)
	go d.csvToChan(chanCsvItem)

	for csvItem := range chanCsvItem {
		if csvItem.Plaintext != "" {
			fmt.Println(csvItem.Plaintext)
		}
	}

	return
}

func (d *DumpDomains) dumpHashCat() {
	_ = d.HashCat.PrintPlaintext()
}

func (d *DumpDomains) csvToChan(chanCsvItem chan CsvItem) {
	err := d.Csv.ReadToChan(chanCsvItem)
	close(chanCsvItem)

	if err != nil {
		d.cnf.Output.Log(err.Error())
	}
}

func (d *DumpDomains) resolveDNS(domain, recordType string) {
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
