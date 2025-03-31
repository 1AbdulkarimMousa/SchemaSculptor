package main

import (
	"log"

	"github.com/1AbdulkarimMousa/SchemaSculptor/handlers"
)

// load configuration, then start application server
func main() {

	// then restart or reload to load compiled queries
	if err := handlers.StartServer(); err != nil {
		log.Fatal(err)
	}
}
