package nsec3walker

type CsvUpdate struct {
	Cracked    *Cracked
	Csv        *Csv
	cnf        *Config
	cntChanged int
}

func NewCsvUpdate(config *Config) (update *CsvUpdate, err error) {
	hashCat, err := NewHashCat(config.FileHashcat, config)
	if err != nil {
		return
	}

	csv, err := NewCsv(config.FileCsv, config.Output)
	if err != nil {
		return
	}

	update = &CsvUpdate{
		Cracked: hashCat.Cracked,
		Csv:     csv,
		cnf:     config,
	}

	return
}

func NewCsvUpdateForData(config *Config, csv *Csv, cracked *Cracked) (update *CsvUpdate) {
	update = &CsvUpdate{
		Cracked: cracked,
		Csv:     csv,
		cnf:     config,
	}

	return
}

func (cu *CsvUpdate) Run() (err error) {
	err = cu.Csv.StartNew()
	if err != nil {
		return
	}

	chanCsvItem := make(chan CsvItem, 10)
	go cu.csvToChan(chanCsvItem)

	for csvItem := range chanCsvItem {
		plaintext, ok, errNow := cu.Cracked.GetForCsvItem(csvItem)
		if errNow != nil {
			return errNow
		}

		if ok && plaintext != csvItem.Plaintext {
			csvItem.Plaintext = plaintext
			cu.cntChanged++
		}

		err = cu.Csv.FileTemp.Insert(csvItem)
		if err != nil {
			return
		}
	}

	err = cu.Csv.Replace()

	return
}

func (cu *CsvUpdate) csvToChan(chanCsvItem chan CsvItem) {
	err := cu.Csv.ReadToChan(chanCsvItem, true)

	if err != nil {
		cu.cnf.Output.Log(err.Error())
	}
}
