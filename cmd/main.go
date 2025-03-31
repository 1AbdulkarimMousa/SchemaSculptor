package main

import (
	"fmt"

	"github.com/1AbdulkarimMousa/SchemaSculptor/agent"
)

func buildQueries() {
	agent.BuildQueries()
	fmt.Println("Queries built successfully.")
}

func main() {
	buildQueries()
}
