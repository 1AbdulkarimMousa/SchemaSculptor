module github.com/1AbdulkarimMousa/SchemaSculptor/agent

replace github.com/1AbdulkarimMousa/SchemaSculptor/util => ./../util

go 1.22.2

require (
	github.com/1AbdulkarimMousa/SchemaSculptor/util v0.0.0-00010101000000-000000000000
	github.com/lib/pq v1.10.9
)

require (
	github.com/joho/godotenv v1.5.1 // indirect
	golang.org/x/crypto v0.11.0 // indirect
)
