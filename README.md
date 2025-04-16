# Status 
Project is still under constructions.

# Introduction

Throughout my career, I’ve worked on many projects and encountered a wide range of authentication methods, queue implementations, and message broker technologies across different programming languages. I’ve explored various ways to interact with databases—from hardcoding queries to complex query builders, safe ORMs, escaping techniques for preventing injection attacks, and basic driver setups. As a result, my technical debt has become quite significant, almost like Mount Everest. To stay future-proof and avoid the hassle of maintaining multiple versions of the same implementation across different technologies (a lesson learned from managing my technical debt), I’ve decided to focus on Golang and PostgreSQL moving forward. While I have respect for C++ and Rust, I find Golang to be the most appealing choice for my future projects.

In the SchemaSculptor project, I plan to fuse the finest pieces of code I've crafted over the years to create the most efficient and maintainable design pattern imaginable. My aim is to build a project that completely bypasses the "fire triangle" of fuel, oxygen, and spark—avoiding the pitfalls of pointers, memory leaks, and unoptimized algorithms/excessive complexity.

SchemaSculptor aims to return the responsibility of data algorithms to PostgreSQL. This means we’re left facing challenges like pointers and memory leaks, i.e., the fuel and the spark. The project is designed to leverage an SQL compiler, `sqlc`, to ensure the compiled code doesn't have leaks. As a result, we eliminate the risk of sparks igniting the fuels, i.e., memory leakage.

Don’t get me wrong; I have a genuine appreciation for memory management. However, as more people get involved in the project, constantly chasing pointers becomes impractical, especially when there are very experienced people from different domains, each having his or her own way of memory management.

As a result, implementers will be able to focus more on solving business logic challenges in the most elegant way, without being overly concerned about the underlying technology. This approach aims to minimize technical debt as much as possible.

That being said, embracing the Unix philosophy of "one tool for one task" leads to easier code maintenance. This approach reduces the fear of switching companies every two years, as it minimizes technical debt and allows developers to move confidently without being bogged down by complex systems.

Finally, as LLM coding models gain traction in the industry, and as unexperienced new prompt engineers are diverging from the clean reliable effecient maintainable approach, SchemaSculptor aims to provide guidance with better approach for prompters and experienced implementors. With implementor supervision and automation, it will deliver high-quality backend technology that outperforms every data application on the market.

## Prerequisites

- PostgreSQL installed and running
- Go installed (1.18+)
- Access to a Postgresql Server 

## Getting Started

1. Clone the repository:
   ```
   git clone https://github.com/1AbdulkarimMousa/SchemaSculptor
   cd sculptor
   ```

2. Create an `.env` file:
   ```
   make .env
   ```
   This creates a default `.env` file. You should edit it with your actual configuration values.

3. Run the full setup:
   ```
   make setup
   ```
   This will set up everything using values from your `.env` file.

## Available Commands

### Environment Management

- `make check-env` - Displays the current environment variables loaded from `.env`
- `make .env` - Creates a default `.env` file if one doesn't exist

### Database Management

- `make db-setup` - Creates the database and user using values from `.env`
- `make db-destroy` - Drops the database and user specified in `.env`
- `make load-schema` - Loads the schema into the database using `.env` credentials

### Development Tools

- `make install-sqlc` - Installs the SQLC tool for SQL-to-Go code generation
- `make sqlc-generate` - Generates Go code from SQL queries
- `make go-get` - Installs all required Go packages
- `make run` - Runs the application
- `make test` - Runs all tests

## How Environment Variables Are Used

The Makefile uses environment variables from your `.env` file. When executing commands, it will:

1. Use values from the `.env` file as defaults
2. Allow you to override these values interactively
3. Skip prompts if all required values are already defined

For example, when running `make db-setup`, it will use `DB_USER`, `DB_NAME`, and `DB_PASS` from your `.env` file, but you can provide different values when prompted.

## Environment Variables

Key variables used by the Makefile:

| Variable | Description | Used By |
|----------|-------------|---------|
| DB_HOST | Database host | load-schema |
| DB_PORT | Database port | load-schema |
| DB_NAME | Database name | db-setup, db-destroy, load-schema |
| DB_USER | Database username | db-setup, db-destroy, load-schema |
| DB_PASS | Database password | db-setup, load-schema |
| HTTP_IP | Server IP | run |
| HTTP_PORT | Server port | run |

Key variables used by the auth pkg:

| Variable | Description |
|----------|-------------|
| SMTP_HOST | SMTP Mail Provide host 
| SMTP_PORT | SMTP Mail Provide port 
| SMTP_USER | eMail User  
| SMTP_PASS | eMail Password 

## Best Practices

1. Never commit your `.env` file to version control
2. Keep a `.env.example` file in your repository for reference
3. Run `make check-env` after modifying `.env` to verify your changes
4. Use `make setup` for initial project setup or after major changes
