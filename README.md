# Environment-Aware Makefile

This README explains how to use the environment-aware Makefile for the Valutoria application. The Makefile simplifies common development tasks while using environment variables from your `.env` file.

## Prerequisites

- PostgreSQL installed and running
- Go installed (1.18+)
- `sudo` access (for database operations)

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/valutoria.git
   cd valutoria
   ```

2. Create an `.env` file:
   ```bash
   make .env
   ```
   This creates a default `.env` file. You should edit it with your actual configuration values.

3. Run the full setup:
   ```bash
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

## Best Practices

1. Never commit your `.env` file to version control
2. Keep a `.env.example` file in your repository for reference
3. Run `make check-env` after modifying `.env` to verify your changes
4. Use `make setup` for initial project setup or after major changes

## Customizing the Makefile

If you need to add new targets that depend on environment variables:

1. Add them after the `.env` include line
2. Use `$(VARIABLE_NAME)` syntax to access environment variables
3. Add dependencies on the `.env` target for targets that require environment variables