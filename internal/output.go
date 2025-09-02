package nsec3walker

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
)

type OutputFiles struct {
	HashFile *File
	LogFile  *File
	MapFile  *File
}

type Output struct {
	files   *OutputFiles
	verbose bool
}

func NewFiles(fileAbs string) (files *OutputFiles, err error) {
	files = &OutputFiles{}

	files.HashFile, err = NewFile(fileAbs+SuffixHash, BuffSizeHash)

	if err != nil {
		return
	}

	files.MapFile, err = NewFile(fileAbs+SuffixCsv, BuffSizeCsv)

	if err != nil {
		_ = files.HashFile.Close()

		return
	}

	files.LogFile, err = NewFile(fileAbs+SuffixLog, 0)

	if err != nil {
		_ = files.HashFile.Close()
		_ = files.MapFile.Close()
	}

	return
}

func NewOutput() (output *Output) {
	return &Output{}
}

func (o *Output) SetVerbose(verbose bool) {
	o.verbose = verbose
}

func (o *Output) SetFilePrefix(filePrefix string) (err error) {
	o.files, err = NewFiles(filePrefix)

	return
}

func (fi *OutputFiles) Close() {
	if fi.HashFile != nil {
		_ = fi.HashFile.Close()
	}

	if fi.MapFile != nil {
		_ = fi.MapFile.Close()
	}

	if fi.LogFile != nil {
		_ = fi.LogFile.Close()
	}
}

func (o *Output) Hash(hash string, nsec Nsec3Params) {
	msg := fmt.Sprintf("%s:.%s:%s:%d\n", hash, nsec.domain, nsec.saltString, nsec.iterations)

	if !o.isFileOutput() {
		fmt.Print(msg)

		return
	}

	err := o.files.HashFile.Write(msg)

	if err != nil {
		log.Fatal(err)
	}
}

func (o *Output) Log(message string) {
	log.Println(message)

	if o.isFileOutput() {
		err := o.files.LogFile.Write(message + "\n")

		if err != nil {
			log.Fatal(err)
		}

	}
}

func (o *Output) LogVerbose(message string) {
	if o.verbose {
		o.Log(message)
	}
}

func (o *Output) Fatal(err error) {
	log.Fatal(err)
}

func (o *Output) isFileOutput() bool {
	return o.files != nil
}

func (o *Output) Csv(hash Nsec3Record, nsec Nsec3Params) {
	if !o.isFileOutput() {
		return
	}

	var types []string

	for _, t := range hash.Types {
		types = append(types, dns.TypeToString[t])
	}

	csvItem := CsvItem{
		Hash:       hash.Start,
		HashNext:   hash.End,
		Domain:     nsec.domain,
		Salt:       nsec.saltString,
		Iterations: int(nsec.iterations),
		Plaintext:  "",
		Types:      types,
	}

	msg := csvItem.toCsv()

	err := o.files.MapFile.Write(msg + "\n")

	if err != nil {
		log.Fatal(err)
	}
}

func (o *Output) Close() {
	if o.files != nil {
		o.files.Close()
	}
}

func (o *Output) Logf(s string, params ...interface{}) {
	o.Log(fmt.Sprintf(s, params...))
}

func (o *Output) LogVerbosef(s string, params ...interface{}) {
	if o.verbose {
		o.Log(fmt.Sprintf(s, params...))
	}
}
