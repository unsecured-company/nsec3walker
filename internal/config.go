package nsec3walker

import (
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/net/publicsuffix"
	"os"
	"path/filepath"
	"strings"
)

const (
	ActionDebug           = "debug"
	ActionDumpDomains     = "dump-domains"
	ActionHelp            = "help"
	ActionUpdateCsv       = "update-csv"
	ActionWalk            = "walk"
	CntThreadsPerNs       = 3
	CsvSeparator          = ","
	FlagDomain            = "domain"
	FlagDumpDomains       = ActionDumpDomains
	FlagFileCsv           = "file-csv"
	FlagFileHashcat       = "file-hashcat"
	FlagNameServers       = "nameservers"
	FlagProgress          = "progress"
	FlagQuitAfter         = "quit-after"
	FlagThreads           = "threads"
	FlagUpdateCsv         = ActionUpdateCsv
	GenericServers        = "8.8.8.8:53,8.8.4.4:53,1.1.1.1:53,77.88.8.8"
	HashRegexp            = `^[0-9a-v]{32}$`
	LogCounterIntervalSec = 30
	QuitAfterMin          = 5
)

const UsageRoot = `Usage:
  nsec3walker command [flags]

Main commands:
  walk        Walk zone for a domain
  file        Process CSV & Hashcat files

Additional commands:
  debug       Show debug information for a domain
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
`

type Config struct {
	Action                string
	Domain                string
	DomainDnsServers      []string
	FileCsv               string
	FileHashcat           string
	LogCounterIntervalSec int
	Output                *Output
	QuitAfterMin          int
	QuitOnChange          bool
	Verbose               bool

	cntThreadsPerNs    int
	debugDomain        string
	domainServerInput  string
	dumpDomains        bool
	filePathPrefix     string
	genericDnsServers  []string
	genericServerInput string
	help               bool
	updateCsv          bool
}

func NewConfig() (config *Config, err error) {
	config = &Config{
		Output: NewOutput(),
	}

	long := "Tool for traversing NSEC3 enabled DNS zone"

	rootCmd := &cobra.Command{
		Use:   filepath.Base(os.Args[0]) + " [command] [flags]",
		Short: "Tool for traversing NSEC3 enabled DNS zone",
		Long:  long,
		Run: func(cmd *cobra.Command, args []string) {
			config.help = true
			config.Action = ActionHelp
			cmd.SetUsageTemplate(UsageRoot)
			_ = cmd.Help()
			return
		},
	}

	rootCmd.AddCommand(
		NewDebugCommand(config),
		NewWalkCommand(config),
		NewFileCommand(config),
	)

	err = rootCmd.Execute()

	if err != nil {
		return config, err
	}

	if config.help || config.Action == "" {
		config.Action = ActionHelp

		return config, nil
	}

	config.Output.SetVerbose(config.Verbose)

	if config.filePathPrefix != "" {
		config.filePathPrefix, err = GetOutputFilePrefix(config.filePathPrefix, config.Domain)

		if err == nil {
			err = config.Output.SetFilePrefix(config.filePathPrefix)
		}

		if err != nil {
			return
		}

		config.Output.Log("Logging into " + config.filePathPrefix + ".[log,csv,hash]")
	}

	errs := []error{
		ValueMustBePositive(config.LogCounterIntervalSec, FlagProgress),
		ValueMustBePositive(config.QuitAfterMin, FlagQuitAfter),
		ValueMustBePositive(config.cntThreadsPerNs, FlagThreads),
	}

	for _, errX := range errs {
		if errX != nil {
			return config, errX
		}
	}

	return
}

func NewDebugCommand(config *Config) *cobra.Command {
	var walkCmd = &cobra.Command{
		Use:   "debug [flags]",
		Short: "Show debug information for a domain",
		Long:  "Show debug information for a domain. Provide --domain.",
		Run: func(cmd *cobra.Command, args []string) {
			config.Action = ActionDebug

			if len(args) == 0 && cmd.Flags().NFlag() == 0 {
				config.help = true
				_ = cmd.Help()

				return
			}
		},
	}

	addCommonFlags(walkCmd, config)
	addDomainFlags(walkCmd, config)

	return walkCmd
}

func NewWalkCommand(config *Config) *cobra.Command {

	var walkCmd = &cobra.Command{
		Use:   "walk [flags]",
		Short: "Walk zone for a domain",
		Long:  "Walk zone for a domain. Provide --domain.",
		Run: func(cmd *cobra.Command, args []string) {
			config.Action = ActionWalk

			if len(args) == 0 && cmd.Flags().NFlag() == 0 {
				config.help = true
				_ = cmd.Help()

				return
			}
		},
	}

	walkCmd.Flags().IntVar(&config.LogCounterIntervalSec, FlagProgress, LogCounterIntervalSec, "Counters print interval in seconds")
	walkCmd.Flags().IntVar(&config.QuitAfterMin, FlagQuitAfter, QuitAfterMin, "Quit after X minutes of no new hashes")
	walkCmd.Flags().StringVarP(&config.filePathPrefix, "output", "o", "", "Path and prefix for output files. ../directory/prefix")
	walkCmd.Flags().BoolVar(&config.QuitOnChange, "quit-on-change", false, "Quit if the zone changed")
	walkCmd.Flags().IntVarP(&config.cntThreadsPerNs, FlagThreads, "t", CntThreadsPerNs, "[WIP] Threads per NS server")
	addCommonFlags(walkCmd, config)
	addDomainFlags(walkCmd, config)

	_ = walkCmd.MarkFlagRequired(FlagDomain)

	return walkCmd
}

func NewFileCommand(config *Config) *cobra.Command {
	var updateCsvCmd = &cobra.Command{
		Use:           "file [flags]",
		Short:         "Process CSV & Hashcat files",
		Long:          "Processing of files - dump plaintext domains, update CSV file.",
		SilenceErrors: true,
		Run:           func(cmd *cobra.Command, args []string) {},
		PostRunE: func(cmd *cobra.Command, args []string) error {
			if config.updateCsv && config.dumpDomains {
				return fmt.Errorf("Specify only one of --%s or --%s", FlagUpdateCsv, FlagDumpDomains)
			}

			if config.updateCsv {
				config.Action = ActionUpdateCsv
				if config.FileCsv == "" || config.FileHashcat == "" {
					return fmt.Errorf("Specify --%s and --%s", FlagFileCsv, FlagFileHashcat)
				}
			} else if config.dumpDomains {
				config.Action = ActionDumpDomains
				if config.FileCsv == "" && config.FileHashcat == "" {
					return fmt.Errorf("Specify --%s or --%s", FlagFileCsv, FlagFileHashcat)
				}
			} else {
				return fmt.Errorf("Specify --%s or --%s", FlagUpdateCsv, FlagDumpDomains)
			}

			return nil
		},
	}

	updateCsvCmd.Flags().BoolVar(&config.dumpDomains, FlagDumpDomains, false, "Dump plaintext domains from files (CSV, Hashcat)")
	updateCsvCmd.Flags().BoolVar(&config.updateCsv, FlagUpdateCsv, false, "Update CSV file with plaintext domains from Hashcat")
	updateCsvCmd.Flags().StringVar(&config.FileHashcat, FlagFileHashcat, "", "A Hashcat .potfile file containing cracked hashes")
	updateCsvCmd.Flags().StringVar(&config.FileCsv, FlagFileCsv, "", "A nsec3walker .csv file")
	addCommonFlags(updateCsvCmd, config)

	return updateCsvCmd
}

func addCommonFlags(cmd *cobra.Command, config *Config) {
	cmd.Flags().BoolVarP(&config.Verbose, "verbose", "v", false, "Verbose")
}

func addDomainFlags(cmd *cobra.Command, config *Config) {
	cmd.Flags().StringVar(&config.Domain, FlagDomain, "", "Domain")
	_ = cmd.MarkFlagRequired(FlagDomain) // would return err if FlagDomain wasn't defined above
	cmd.Flags().StringVar(&config.genericServerInput, "resolvers", GenericServers, "Comma-separated list of generic DNS resolvers")
	cmd.Flags().StringVar(&config.domainServerInput, FlagNameServers, "", "Comma-separated list of custom authoritative NS servers for the domain")

	return
}

func (cnf *Config) processAuthNsServers(getFromRoot bool) (err error) {
	cnf.DomainDnsServers = cnf.parseServersValue(cnf.domainServerInput)

	if len(cnf.DomainDnsServers) > 0 {
		return
	}

	domain := cnf.Domain

	if getFromRoot {
		domain, _ = publicsuffix.PublicSuffix(domain)
	}

	genericDnsServers := cnf.parseServersValue(cnf.genericServerInput)
	cnf.Output.Logf("Getting NS servers for [%s] via [%v]", domain, genericDnsServers)

	topCount := 0
	counter := map[string]int{}
	nsResults := map[string][]string{}

	for _, server := range genericDnsServers {
		nss, err := getNameServersFromDnsServer(domain, server)

		if err != nil {
			if errNoConnection(err) {
				cnf.Output.Log("No route to " + server)
			} else {
				cnf.Output.Logf("Error getting NS servers from %s: %v\n", server, err)
			}

			continue
		}

		nsResults[server] = nss
		counter[server] = len(nss)

		if len(nss) > topCount {
			topCount = len(nss)
			cnf.DomainDnsServers = nss
		}
	}

	// will use later
	_ = nsResults
	_ = counter

	if len(cnf.DomainDnsServers) == 0 {
		err = fmt.Errorf("no NS servers found for domain %s", cnf.Domain)
	}

	return
}

func (cnf *Config) parseServersValue(serversStr string) (servers []string) {
	serversStr = strings.Trim(serversStr, ",")
	serversStr = strings.TrimSpace(serversStr)

	if serversStr == "" {
		return
	}

	serversItems := strings.Split(serversStr, ",")

	for _, server := range serversItems {
		server = ParseDnsServerValue(server)
		if server != "" {
			servers = append(servers, server)
		}
	}

	return
}

func ValueMustBePositive(value int, name string) (err error) {
	if value <= 0 {
		err = fmt.Errorf("--%s must be a positive number", name)
	}
	/* I could use `uint`, but I don't like that word in help output. :) */
	return
}
