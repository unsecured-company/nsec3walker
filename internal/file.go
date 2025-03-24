package nsec3walker

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// TODO increase once I have Context and signal handling
	BuffSizeHash = 0
	BuffSizeCsv  = 0
	PermFile     = 0644
	PermDir      = 0755
	SuffixHash   = ".hash"
	SuffixLog    = ".log"
	SuffixCsv    = ".csv"
)

type File struct {
	Name       string
	Pointer    *os.File
	Writer     *bufio.Writer
	BuffSizeKb int // BuffSizeKb size in kbytes; 0 for auto-flush
}

func NewFile(name string, buffSizeKb int) (file *File, err error) {
	fp, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, PermFile)

	if err != nil {
		return
	}

	buffSize := 0

	if buffSizeKb > 0 {
		buffSize = buffSizeKb * 1024
	}

	writer := bufio.NewWriterSize(fp, buffSize)

	file = &File{
		Name:       name,
		Pointer:    fp,
		Writer:     writer,
		BuffSizeKb: buffSizeKb,
	}

	return
}

func (f *File) Write(data string) (err error) {
	_, err = f.Writer.WriteString(data)

	if err == nil && f.BuffSizeKb == 0 {
		err = f.Flush()
	}

	if err != nil {
		err = fmt.Errorf("Error writing to file %s: %s", f.Name, err)
	}

	return
}

func (f *File) Flush() error {
	return f.Writer.Flush()
}

func (f *File) Close() error {
	if err := f.Flush(); err != nil {
		return err
	}

	return f.Pointer.Close()
}

func GetOutputFilePrefix(path string, domain string) (absPath string, err error) {
	absPath, err = getAbsolutePath(path)
	info, err := os.Stat(absPath)

	if err == nil && info.IsDir() {
		return filepath.Join(absPath, createFilePrefix(domain)), nil
	}

	return
}

func getAbsolutePath(path string) (absPath string, err error) {
	absPath = filepath.Clean(path)
	absPath, err = filepath.Abs(absPath)
	_, err = os.Stat(absPath)

	if os.IsNotExist(err) {
		dir := filepath.Dir(absPath)
		_, err = os.Stat(dir)

		if err != nil {
			err = os.MkdirAll(dir, PermDir)
		}
	}

	return
}

func createFilePrefix(domain string) (prefix string) {
	date := time.Now().Format("2006_01_02-15_04") // 2025_02_24-13_59

	return domain + "-" + date
}
