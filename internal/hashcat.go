package nsec3walker

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const (
	CntHashcatPotParts = 5
)

type HashCat struct {
	PotFile *os.File
	Count   int
	out     *Output
	cnf     Config
	Domains map[string]map[string]string
	// ".cz|salt|iterations" -> "" -> "c17odk0qjlecpl8eldnctr21vpck06bq" -> "abtest"
}

func NewHashCat(potFilePath string, out *Output, cnf Config) (hashCat *HashCat, err error) {
	potFile, err := os.OpenFile(potFilePath, os.O_RDONLY, 0)

	if err != nil {
		return
	}

	hashCat = &HashCat{
		PotFile: potFile,
		Domains: make(map[string]map[string]string),
		out:     out,
		cnf:     cnf,
	}

	err = hashCat.load()

	out.Logf("Hashcat pot file has %d NSEC3 hashes.", hashCat.Count)

	if cnf.Verbose {
		hashCat.printVerboseCounts()
	}

	return
}

func (h *HashCat) load() (err error) {
	re := regexp.MustCompile(HashRegexp)
	scanner := bufio.NewScanner(h.PotFile)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")

		//c17odk0qjlecpl8eldnctr21vpck06bq:.cz:cb6658404d098de6:0:abtest
		// 0 hash | 1 domain | 2 salt | 3 iterations | 4 plaintext
		if len(parts) != CntHashcatPotParts || !re.MatchString(parts[0]) {
			h.out.LogVerbose("Invalid line: " + line)
			continue
		}

		domain := parts[4] + parts[1]
		key := getHashcatMapKey(parts[1], parts[2], parts[3])
		hash := parts[0]

		if _, ok := h.Domains[key]; !ok {
			h.Domains[key] = make(map[string]string)
		}

		h.Domains[key][hash] = domain
		h.Count++
	}

	if err := scanner.Err(); err != nil {
		err = fmt.Errorf("error reading Hashcat Pot file: %s", err)
	}

	return
}

func (h *HashCat) printVerboseCounts() {
	var domainsCount string

	for key, hashes := range h.Domains {
		cnt := len(hashes)
		parts := strings.Split(key, "|")
		domainsCount += fmt.Sprintf("| %d %s ", cnt, strings.Trim(parts[0], "."))
	}

	h.out.LogVerbosef("Hashcat counts: %d all %s", h.Count, domainsCount)
}

func getHashcatMapKey(domain string, salt string, iterations interface{}) string {
	domain = strings.Trim(domain, ".")

	return fmt.Sprintf("%s|%s|%v", domain, salt, iterations)
}
