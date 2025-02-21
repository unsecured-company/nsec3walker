package main

import (
	"log"

	nsec3walker "github.com/vitezslav-lindovsky/nsec3walker/internal"
)

func main() {
	var err error
	config := initConfig()
	output := initOutput(config)
	nw := nsec3walker.NewNSec3Walker(config, output)

	switch config.Action {
	case nsec3walker.ActionDebug:
		err = nw.RunDebug()
	case nsec3walker.ActionWalk:
		err = nw.RunWalk()
	case nsec3walker.ActionDump:
		err = nw.RunDump()
	}

	output.Close()

	if err != nil {
		output.Fatal(err)
	}
}

func initConfig() (config nsec3walker.Config) {
	config, err := nsec3walker.NewConfig()

	if err != nil {
		log.Fatal(err)
	}

	return
}

func initOutput(config nsec3walker.Config) (output *nsec3walker.Output) {
	output, err := nsec3walker.NewOutput(config.FilePathPrefix, config.Verbose)

	if err != nil {
		log.Fatal(err)
	}

	return
}
