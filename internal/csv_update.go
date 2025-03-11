package nsec3walker

type CsvUpdate struct {
	HashCat    *HashCat
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
		HashCat: hashCat,
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
		key := getHashcatMapKey(csvItem.Domain, csvItem.Salt, csvItem.Iterations)
		_, ok := cu.HashCat.Domains[key]

		if ok {
			plaintext, ok := cu.HashCat.Domains[key][csvItem.Hash]

			if ok && plaintext != csvItem.Plaintext {
				csvItem.Plaintext = plaintext
				cu.cntChanged++
			}
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
	err := cu.Csv.ReadToChan(chanCsvItem)
	close(chanCsvItem)

	if err != nil {
		cu.cnf.Output.Log(err.Error())
	}
}
