package nsec3walker

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const (
	CntCsvFileParts = 7
)

type Csv struct {
	FileInput *CsvFile
	FileTemp  *CsvFile
	out       *Output
}

type CsvFile struct {
	Resource *os.File
	Path     string
	Size     int64
	CntLines int
}

type CsvItem struct {
	Hash       string
	HashNext   string
	Domain     string
	Salt       string
	Iterations int
	Plaintext  string
	Types      []string
}

func NewCsvFile(filePath string, isNew bool) (csvFile *CsvFile, err error) {
	openFlag := os.O_RDONLY
	openPerm := os.FileMode(0)

	if isNew {
		openFlag = os.O_CREATE | os.O_TRUNC | os.O_WRONLY
		openPerm = PermFile
	}

	csvFileRes, err := os.OpenFile(filePath, openFlag, openPerm)

	if err != nil {
		return
	}

	info, err := os.Stat(filePath)

	if err != nil {
		return
	}

	csvFile = &CsvFile{
		Resource: csvFileRes,
		Path:     filePath,
		Size:     info.Size(),
	}

	return
}

func NewCsv(csvFilePath string, out *Output) (csv *Csv, err error) {
	csvFileRes, err := NewCsvFile(csvFilePath, false)

	csv = &Csv{
		FileInput: csvFileRes,
		out:       out,
	}

	cntValid, cntInvalid, err := csv.analyze()

	if err != nil {
		return
	}

	msg := "csv file has %d valid lines"

	if cntInvalid > 0 {
		err = fmt.Errorf(msg+" and %d invalid. Fix them before continuing.", cntValid, cntInvalid)

		return
	}

	out.Logf(msg+".", cntValid)

	return
}

func (c *Csv) ReadToChan(chanCsvItem chan CsvItem) (err error) {
	_, err = c.FileInput.Resource.Seek(0, io.SeekStart)

	if err != nil {
		return fmt.Errorf("Failed to seek to the beginning of the file: %v", err)
	}

	scanner := bufio.NewScanner(c.FileInput.Resource)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		chanCsvItem <- c.csvLineToStruct(line)
	}

	err = scanner.Err()

	if err != nil {
		return fmt.Errorf("Failed to read the csv file: %v", err)
	}

	return
}

func (c *Csv) StartNew() (err error) {
	fileTempPath := c.FileInput.Path + ".tmp"
	c.FileTemp, err = NewCsvFile(fileTempPath, true)

	if err != nil {
		err = fmt.Errorf("Failed to create temporary csv file: %v", err)
	}

	return
}

func (cf *CsvFile) Insert(item CsvItem) (err error) {
	cntWritten, err := cf.Resource.WriteString(item.toCsv() + "\n")

	if err != nil {
		return fmt.Errorf("Failed to write to the temporary csv file: %v", err)
	}

	cf.Size += int64(cntWritten)

	return nil
}

func (c *Csv) analyze() (cntValid int, cntInvalid int, err error) {
	re := regexp.MustCompile(HashRegexp)
	scanner := bufio.NewScanner(c.FileInput.Resource)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		parts := strings.Split(line, CsvSeparator)

		if len(parts) == CntCsvFileParts {
			_, err = strconv.Atoi(parts[4])

			if err == nil && re.MatchString(parts[0]) && re.MatchString(parts[1]) {
				cntValid++
				continue
			}
		}

		c.out.Log("Invalid line: " + line)
		cntInvalid++
	}

	err = scanner.Err()

	if err != nil {
		err = fmt.Errorf("error reading file <%s>: %s", c.FileInput.Path, err)
	}

	return
}

func (c *Csv) csvLineToStruct(line string) CsvItem {
	parts := strings.Split(line, CsvSeparator)
	iterInt, _ := strconv.Atoi(parts[4])

	return CsvItem{
		Hash:       parts[0],
		HashNext:   parts[1],
		Domain:     parts[2],
		Salt:       parts[3],
		Iterations: iterInt,
		Plaintext:  parts[5],
		Types:      strings.Split(parts[6], ","),
	}
}

func (c *Csv) Replace() (err error) {
	if c.FileInput.Size > c.FileTemp.Size {
		return fmt.Errorf("Temporary file is smaller than the original one. Something went wrong.")
	}

	_ = c.FileInput.Resource.Close()
	_ = c.FileTemp.Resource.Close()

	err = os.Rename(c.FileTemp.Path, c.FileInput.Path)

	if err != nil {
		return fmt.Errorf("Failed to replace the original csv file: %v", err)
	}

	return
}

func (cl CsvItem) toCsv() string {
	items := []string{
		cl.Hash,
		cl.HashNext,
		cl.Domain,
		cl.Salt,
		strconv.Itoa(cl.Iterations),
		cl.Plaintext,
		strings.Join(cl.Types, "|"),
	}

	return strings.Join(items, CsvSeparator)
}
