package nsec3walker

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

const (
	ActionDebug           = "debug"
	ActionDump            = "dump"
	ActionHelp            = "help"
	ActionWalk            = "walk"
	FlagFileCsv           = "file-csv"
	FlagFileHashcat       = "file-hashcat"
	FlagThreads           = "threads"
	FlagQuitAfter         = "quit-after"
	FlagProgress          = "progress"
	CntThreadsPerNs       = 2
	CsvSeparator          = ","
	GenericServers        = "8.8.8.8:53,1.1.1.1:53,9.9.9.9:53"
	HashRegexp            = `^[0-9a-v]{32}$`
	LogCounterIntervalSec = 30
	QuitAfterMin          = 15
)

type Config struct {
	Action                string
	DebugDomain           string
	Domain                string
	DomainDnsServers      []string
	FileCsv               string
	FileHashcat           string
	FilePathPrefix        string
	GenericDnsServers     []string
	Help                  bool
	LogCounterIntervalSec int
	QuitAfterMin          int
	StopOnChange          bool
	Verbose               bool
	cntThreadsPerNs       int
}

func NewConfig() (config Config, err error) {
	long := "A tool for traversing NSEC3 DNS hashes for a specified domain using its authoritative NS servers.\n"
	long += "Flags marked as [WIP] indicate features that are still in development and may change in the future.\n"

	var rootCmd = &cobra.Command{
		Use:           filepath.Base(os.Args[0]) + " [flags] domain",
		Short:         "NSEC3 Walker - Discover and traverse NSEC3 DNS hashes",
		Long:          long,
		Args:          cobra.ArbitraryArgs,
		SilenceErrors: true,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 && cmd.Flags().NFlag() == 0 {
				config.Help = true
				_ = cmd.Help()

				return
			}

			if len(args) > 0 {
				config.Domain = args[0]
			}
		},
	}

	var genericServerInput string
	var domainServerInput string

	rootCmd.Flags().StringVar(&genericServerInput, "resolver", GenericServers, "Comma-separated list of generic DNS resolvers")
	rootCmd.Flags().StringVar(&domainServerInput, "domain-ns", "", "Comma-separated list of custom authoritative NS servers for the domain")
	rootCmd.Flags().BoolVarP(&config.Verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.Flags().BoolVarP(&config.Help, "help", "h", false, "Help!")
	rootCmd.Flags().IntVar(&config.LogCounterIntervalSec, FlagProgress, LogCounterIntervalSec, "Counters print interval in seconds")
	rootCmd.Flags().IntVar(&config.QuitAfterMin, FlagQuitAfter, QuitAfterMin, "Quit after X minutes of no new hashes")
	rootCmd.Flags().StringVar(&config.DebugDomain, "debug-domain", "", "Print debug info for a specified domain")
	rootCmd.Flags().StringVarP(&config.FilePathPrefix, "output", "o", "", "Path and prefix for output files. ../directory/prefix")
	rootCmd.Flags().BoolVar(&config.StopOnChange, "stop-on-change", false, "Stop the walker if the zone changed")
	rootCmd.Flags().StringVar(&config.FileHashcat, FlagFileHashcat, "", "[WIP] A Hashcat .potfile file containing cracked hashes")
	rootCmd.Flags().StringVar(&config.FileCsv, FlagFileCsv, "", "[WIP] A nsec3walker .csv file")
	rootCmd.Flags().IntVarP(&config.cntThreadsPerNs, FlagThreads, "t", CntThreadsPerNs, "[WIP] Threads per NS server")

	if err := rootCmd.Execute(); err != nil {
		return config, err
	}

	if config.Help {
		return config, nil
	}

	errs := []error{
		ValueMustBePositive(config.LogCounterIntervalSec, FlagProgress),
		ValueMustBePositive(config.QuitAfterMin, FlagQuitAfter),
		ValueMustBePositive(config.cntThreadsPerNs, FlagThreads),
	}

	for _, err := range errs {
		if err != nil {
			return config, err
		}
	}

	config.GenericDnsServers = parseDnsServers(genericServerInput)
	config.DomainDnsServers = parseDnsServers(domainServerInput)

	if config.Domain != "" && len(config.DomainDnsServers) == 0 {
		config.DomainDnsServers, err = getAuthNsServers(config.Domain, config.GenericDnsServers)
	}

	if config.FilePathPrefix != "" {
		config.FilePathPrefix, err = GetOutputFilePrefix(config.FilePathPrefix, config.Domain)
	}

	setHashcatFile := config.FileHashcat != ""
	setCsvFile := config.FileCsv != ""
	setFullDump := setHashcatFile && setCsvFile

	if !setFullDump && (setHashcatFile || setCsvFile) {
		err = fmt.Errorf("Both %s and %s has to be set", FlagFileCsv, FlagFileHashcat)

		return
	}

	if config.DebugDomain != "" {
		config.Action = ActionDebug
	} else if setFullDump {
		config.Action = ActionDump
	} else if config.Help {
		config.Action = ActionHelp
	} else {
		config.Action = ActionWalk
	}

	if config.Action == ActionWalk && config.Domain == "" {
		err = fmt.Errorf("Provide a domain to walk")
	}

	return
}

func ValueMustBePositive(value int, name string) (err error) {
	if value <= 0 {
		err = fmt.Errorf("--%s must be a positive number", name)
	}
	/* I could use `uint`, but I don't like that word in Help output. :) */
	return
}
