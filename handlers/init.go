// handlers/init.go
package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strconv"

	"github.com/1AbdulkarimMousa/SchemaSculptor/db"
	"github.com/1AbdulkarimMousa/SchemaSculptor/util"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"github.com/valyala/fasttemplate"
	gomail "gopkg.in/mail.v2"
)

// Global variables for shared components
var (
	router                *gin.Engine
	queries               *db.Queries
	tokenMaker            *PasetoMaker
	verifyAccountTemplate *fasttemplate.Template
	resetPasswordTemplate *fasttemplate.Template
	verifications         = make(map[string]VerificationData)
	smtpDialer            *gomail.Dialer
)

// Consolidated initialization function
func init() {
	// 1. Load environment variables first
	if err := util.LoadEnv("./.env"); err != nil {
		log.Println("Warning: Error loading environment variables:", err)
	}
	log.Println("Environment variables loaded (or skipped)")

	// 2. Initialize database connection
	connectionString := fmt.Sprintf(
		"postgresql://%s:%s@%s:%s/%s?sslmode=%s",
		util.DBUser, util.DBPass, util.DBHost, util.DBPort, util.DBName, util.DBSSl,
	)
	dbConn, err := sql.Open("postgres", connectionString)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	if err := dbConn.Ping(); err != nil {
		log.Fatalf("failed to ping database: %v", err)
	}
	// Initialize the SQLC queries struct with the database connection
	// And prepare the prepared statements
	ctx := context.Background()
	preparedQueries, err := db.Prepare(ctx, dbConn)
	if err != nil {
		log.Fatalf("failed to prepare queries: %v", err)
	}
	queries = preparedQueries
	log.Println("Database connected and queries prepared successfully")

	// 3. Initialize token maker
	tokenMaker, err = NewPaseto(util.PasetoKey)
	if err != nil {
		log.Fatalf("failed to create token maker: %v", err)
	}
	log.Println("Token maker initialized")

	// 4. Initialize email templates
	verifyAccountTemplate = fasttemplate.New(verifyMsg, "[", "]")
	resetPasswordTemplate = fasttemplate.New(resetMsg, "[", "]")
	log.Println("Email templates initialized")

	// 5. Initialize SMTP
	smtpPort, _ := strconv.Atoi(util.SMTPPort)
	smtpDialer = gomail.NewDialer(util.SMTPHost, smtpPort, util.SMTPUser, util.SMTPPass)
	log.Println("SMTP dialer initialized")

	// 6. Initialize router
	router = gin.Default()
	log.Println("Gin router initialized")

	// 7. Setup Authentication Routes (using the function from auth.go)
	SetupAuthRoutes(router, tokenMaker)
	log.Println("Authentication routes initialized")

	// Add other route setups here if needed, e.g.:
	// SetupOtherRoutes(router)

}

// Public function to start the server
func StartServer() error {
	address := util.HTTPIP + ":" + util.HTTPPort
	log.Printf("Server starting on %s", address)
	return router.Run(address)
}
