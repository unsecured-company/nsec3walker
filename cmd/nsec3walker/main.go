package main

import (
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
	err = nw.Run()

	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
}
