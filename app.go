package main

import (
	"log"

	"github.com/1AbdulkarimMousa/SchemaSculptor/handlers"
)

// load configuration, then start application server
func main() {
	if err := handlers.StartServer(); err != nil {
		log.Fatal(err)
	}
}
