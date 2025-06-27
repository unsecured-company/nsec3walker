package main

import (
	"fmt"
	"log"
	"os"

	"github.com/unsecured-company/nsec3walker/internal"
)

const Version = "2.0.3-250628"

func main() {
	_, _ = fmt.Fprintln(os.Stderr, "nsec3walker "+Version+" | https://unsecured.company")

	var err error
	config := initConfig()
	nw := nsec3walker.NewNSec3Walker(config)
	defer config.Output.Close()

	switch config.Action {
	case nsec3walker.ActionHelp:
		os.Exit(0)
	case nsec3walker.ActionWalk:
		err = nw.RunWalk()
	case nsec3walker.ActionDebug:
		err = nw.RunDebug()
	case nsec3walker.ActionUpdateCsv:
		err = nw.RunCsvUpdate()
	case nsec3walker.ActionDumpDomains:
		err = nw.RunDumpDomains()
	}

	if err != nil {
		config.Output.Fatal(err)
	}
}

func initConfig() (config *nsec3walker.Config) {
	config, err := nsec3walker.NewConfig()

	if err != nil {
		log.Fatal(err)
	}

	return
}
