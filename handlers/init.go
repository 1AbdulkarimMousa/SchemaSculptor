// handlers/init.go
package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/1AbdulkarimMousa/SchemaSculptor/db"
	"github.com/1AbdulkarimMousa/SchemaSculptor/util"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	gomail "gopkg.in/mail.v2"
)

// Import missing from go.mod:
// go get github.com/gorilla/websocket

// Global variables for shared components
var (
	router        *gin.Engine
	queries       *db.Queries
	tokenMaker    *pasetoMaker
	verifications = make(map[string]VerificationData)
	smtpDialer    *gomail.Dialer

	// WebSocket upgrader
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins in development; should be restricted in production
		},
	}

	// Collaborative editing globals
	collaborativeMutex    sync.RWMutex
	collaborativeRegistry map[string][]byte              // The shared registry document
	editorSessions        map[string][]*EditorConnection // Map of registry ID to connected editors
	partnerColors         map[int32]string               // Map of partner IDs to their assigned colors
	autosaveInterval      = 30 * time.Second             // Interval for auto-saving the registry to database
)

// EditorConnection represents a connected editor's websocket connection
type EditorConnection struct {
	PartnerID  int32
	Email      string
	Connection *websocket.Conn
	CursorPos  CursorPosition
	Color      string
	Tab        int
}

// CursorPosition represents a cursor position in the document
type CursorPosition struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// EditorMessage represents messages exchanged in the collaborative editor
type EditorMessage struct {
	Type      string         `json:"type"`
	Content   string         `json:"content,omitempty"`
	CursorPos CursorPosition `json:"cursor_pos,omitempty"`
	PartnerID int32          `json:"partner_id"`
	Email     string         `json:"email"`
	Color     string         `json:"color,omitempty"`
	Tab       int            `json:"tab,omitempty"`
	Registry  string         `json:"registry,omitempty"`
}

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
	tokenMaker, err = newPaseto(util.PasetoKey)
	if err != nil {
		log.Fatalf("failed to create token maker: %v", err)
	}
	log.Println("Token maker initialized")

	// 5. Initialize SMTP
	smtpPort, _ := strconv.Atoi(util.SMTPPort)
	smtpDialer = gomail.NewDialer(util.SMTPHost, smtpPort, util.SMTPUser, util.SMTPPass)
	log.Println("SMTP dialer initialized")

	// 6. Initialize collaborative editor maps
	collaborativeRegistry = make(map[string][]byte)
	editorSessions = make(map[string][]*EditorConnection)
	partnerColors = make(map[int32]string)
	log.Println("Collaborative editor structures initialized")

	// 7. Initialize router
	router = gin.Default()
	log.Println("Gin router initialized")

	// 8. Setup Authentication Routes (using the function from auth.go)
	log.Println("Authentication routes initialized")

	// 9. Start autosave goroutine
	go startAutosaveRegistry()
}

// Public function to start the server
func StartServer() error {
	address := util.HTTPIP + ":" + util.HTTPPort
	log.Printf("Server starting on %s", address)
	return router.Run(address)
}

// startAutosaveRegistry periodically saves all registries to the database
func startAutosaveRegistry() {
	ticker := time.NewTicker(autosaveInterval)
	defer ticker.Stop()

	for {
		<-ticker.C
		saveAllRegistries()
	}
}

// saveAllRegistries saves all registries to the database
func saveAllRegistries() {
	collaborativeMutex.RLock()
	defer collaborativeMutex.RUnlock()

	for registryID, content := range collaborativeRegistry {
		// This assumes you have a database table for storing registries
		// You may need to adapt this to your actual schema
		log.Printf("Auto-saving registry %s", registryID)

		// Implement your database save logic here using saveRegistryToDatabase
		err := saveRegistryToDatabase(registryID, content)
		if err != nil {
			log.Printf("Error auto-saving registry %s: %v", registryID, err)
		}
	}
}

// saveRegistryToDatabase saves a registry to the database
func saveRegistryToDatabase(registryID string, content []byte) error {
	// This is a placeholder function for saving to database
	// TODO: Implement database saving logic based on your schema
	log.Printf("Saving registry %s to database (%d bytes)", registryID, len(content))

	// Example implementation (uncomment and adapt to your schema):
	// ctx := context.Background()
	// err := queries.UpsertRegistry(ctx, db.UpsertRegistryParams{
	//     ID:      registryID,
	//     Content: content,
	// })
	// return err

	return nil
}
