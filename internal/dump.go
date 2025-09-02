package nsec3walker

import (
	"fmt"
	"strings"
)

type Dump struct {
	full    bool
	cnf     *Config
	hashCat *HashCat
	csv     *Csv
}

func NewDump(config *Config) (dump *Dump, err error) {
	dump = &Dump{
		full:    config.dumpDomains,
		cnf:     config,
		csv:     nil,
		hashCat: nil,
	}

	if config.FileHashcat != "" {
		dump.hashCat, err = NewHashCat(config.FileHashcat, config)

		if err != nil {
			return
		}
	}

	if config.FileCsv != "" {
		dump.csv, err = NewCsv(config.FileCsv, config.Output)

		if err != nil {
			return
		}
	}

	return
}

func (d *Dump) Run() (err error) {
	if d.csv != nil {
		d.dumpCsv()
	}

	if d.hashCat != nil {
		d.dumpHashCat()
	}

	return
}

func (d *Dump) dumpCsv() {
	chanCsvItem := make(chan CsvItem, 10)
	go d.csvToChan(chanCsvItem)

	for csvItem := range chanCsvItem {
		if csvItem.Plaintext != "" {
			if d.full {
				fmt.Println(csvItem.Plaintext)
			} else {
				fmt.Println(strings.TrimSuffix(csvItem.Plaintext, "."+csvItem.Domain))
			}
		}
	}

	return
}

func (d *Dump) dumpHashCat() {
	if d.full {
		d.hashCat.PrintPlaintextFull()
	} else {
		d.hashCat.PrintPlaintextWordlist()
	}
}

func (d *Dump) csvToChan(chanCsvItem chan CsvItem) {
	err := d.csv.ReadToChan(chanCsvItem, true)

	if err != nil {
		d.cnf.Output.Log(err.Error())
	}
}
