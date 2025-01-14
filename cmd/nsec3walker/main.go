package main

import (
	"fmt"
	nsec3walker "github.com/vitezslav-lindovsky/nsec3walker/internal"
	"log"
)

func main() {
	config, err := nsec3walker.NewConfig()

	if err != nil {
		log.Fatalf("Error - %v\n", err)
	}

	if config.Help {
		return
	}

	if config.Domain == "" {
		log.Fatalf("Provide a domain to walk.\n")
	}

	nw := nsec3walker.NewNSec3Walker(config)

	if config.DebugDomain != "" {
		err = nw.RunDebug(config.DebugDomain)

		x := nsec3walker.NewRangeIndex()
		fmt.Println(x)

	} else {
		err = nw.Run()
	}

	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
}
