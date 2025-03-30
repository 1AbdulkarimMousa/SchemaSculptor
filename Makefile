# Use bash instead of sh
SHELL := /bin/bash

# Database setup
.PHONY: db-setup
db-setup:
	@read -p "Enter database username: " username; \
	read -p "Enter database name: " dbname; \
	read -s -p "Enter database password: " password; \
	echo; \
	sudo -u postgres psql -c "CREATE ROLE $$username WITH ENCRYPTED PASSWORD '$$password';" ; \
	sudo -u postgres psql -c "CREATE DATABASE $$dbname OWNER $$username;" ; \
	sudo -u postgres psql -c "ALTER ROLE $$username WITH LOGIN;" ; \
	sudo -u postgres psql -d $$dbname -c "GRANT ALL PRIVILEGES ON DATABASE $$dbname TO $$username;" ; \
	sudo -u postgres psql -d $$dbname -c "GRANT USAGE, CREATE ON SCHEMA public TO $$username;"
		
.PHONY: db-destroy

db-destroy:
	@read -p "Enter database username: " user; \
	read -p "Enter database name: " dbname; \
	echo; \
	sudo -u postgres psql -c "DROP DATABASE IF EXISTS $$dbname;" ; \
	sudo -u postgres psql -c "DROP USER IF EXISTS $$user;"

	
.PHONY: load-schema
load-schema:
	@read -p "Enter database username: " username; \
	read -p "Enter database name: " dbname; \
	read -s -p "Enter database password: " password; \
	echo; \
	PGPASSWORD=$$password psql -h localhost -U $$username -d $$dbname -f ./db/schema/schema.sql

# SQLC installation
.PHONY: install-sqlc
install-sqlc:
	sudo snap install sqlc
	go install github.com/kyleconroy/sqlc/cmd/sqlc@latest

# Generate Go functions from SQL queries
.PHONY: sqlc-generate
sqlc-generate:
	sqlc generate

# Go package management
.PHONY: go-get
go-get:
	go get github.com/lib/pq
	go get github.com/stretchr/testify
	go get github.com/json-iterator/go
	go get github.com/gorilla/mux
	go get github.com/valyala/fasttemplate
	go get github.com/valyala/quicktemplate
	go get github.com/o1egl/paseto
	go get github.com/gin-gonic/gin
	go get github.com/aead/chacha20poly1305
	go get github.com/google/uuid
	go get github.com/stripe/stripe-go/v81
	go get github.com/joho/godotenv
	go get github.com/gorilla/websocket
	go get github.com/hpcloud/tail
	go get github.com/mattn/go-sqlite3
	
# Run tests
.PHONY: test
test:
	go test -v --cover ./...

# Full setup
.PHONY: setup
setup: db-setup load-schema install-sqlc go-get sqlc-generate