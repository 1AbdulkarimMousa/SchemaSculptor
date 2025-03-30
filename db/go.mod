module github.com/1AbdulkarimMousa/SchemaSculptor/db

replace github.com/1AbdulkarimMousa/SchemaSculptor/util => ./../util

go 1.18

require (
	github.com/1AbdulkarimMousa/SchemaSculptor/util v0.0.0-00010101000000-000000000000
	github.com/lib/pq v1.10.9
	github.com/stretchr/testify v1.8.4
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stripe/stripe-go/v81 v81.4.0 // indirect
	golang.org/x/crypto v0.11.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
