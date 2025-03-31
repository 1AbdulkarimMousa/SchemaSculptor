// handlers/ws.go
package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// Colors for different partners
var partnerColorPalette = []string{
	"#FF5733", "#33FF57", "#3357FF", "#FF33A8",
	"#33A8FF", "#A833FF", "#FF8C33", "#33FFC5",
	"#C533FF", "#FFCB33", "#33FFCB", "#FF33CB",
	"#33CBFF", "#CB33FF", "#FFCB33", "#33FFCB",
}

// Constants for message types
const (
	MessageTypeJoin         = "join"
	MessageTypeLeave        = "leave"
	MessageTypeEdit         = "edit"
	MessageTypeCursorMove   = "cursor_move"
	MessageTypeTabChange    = "tab_change"
	MessageTypeFullDocument = "full_document"
	MessageTypeError        = "error"
)

// Mutex for handling color assignment
var colorMutex sync.Mutex

// handleWebSocketConnection handles WebSocket connections
// This is the original handler from routes.go, preserved for backward compatibility
func handleWebSocketConnection(ctx *gin.Context) {
	// Get payload (authenticated user)
	payload, err := GetPayload(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": ErrInvalidPayload})
		return
	}

	// Verify partner still exists and is active
	partner, err := queries.GetPartnerByEmail(ctx, payload.Email)
	if err != nil || !partner.Active {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": ErrAccountNotActive})
		return
	}

	// Upgrade connection to WebSocket
	conn, err := upgrader.Upgrade(ctx.Writer, ctx.Request, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection to WebSocket: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("WebSocket connection established for user: %s (ID: %d)", payload.Email, payload.PartnerID)

	// Simple ping-pong to keep the connection alive
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Error reading message: %v", err)
			break
		}

		// Echo the message back
		if err := conn.WriteMessage(messageType, message); err != nil {
			log.Printf("Error writing message: %v", err)
			break
		}
	}
}

// assignColorToPartner assigns a color to a partner
func assignColorToPartner(partnerID int32) string {
	colorMutex.Lock()
	defer colorMutex.Unlock()

	// If partner already has a color, return it
	if color, exists := partnerColors[partnerID]; exists {
		return color
	}

	// Otherwise, assign a new color
	colorIndex := int(partnerID) % len(partnerColorPalette)
	color := partnerColorPalette[colorIndex]
	partnerColors[partnerID] = color
	return color
}

// addEditorToSession adds an editor to a session
func addEditorToSession(registryID string, conn *EditorConnection) {
	collaborativeMutex.Lock()
	defer collaborativeMutex.Unlock()

	if _, exists := editorSessions[registryID]; !exists {
		editorSessions[registryID] = make([]*EditorConnection, 0)
	}

	editorSessions[registryID] = append(editorSessions[registryID], conn)
	log.Printf("Editor %s (ID: %d) added to registry %s", conn.Email, conn.PartnerID, registryID)
}

// removeEditorFromSession removes an editor from a session
func removeEditorFromSession(registryID string, conn *EditorConnection) {
	collaborativeMutex.Lock()
	defer collaborativeMutex.Unlock()

	sessions, exists := editorSessions[registryID]
	if !exists {
		return
	}

	for i, session := range sessions {
		if session.PartnerID == conn.PartnerID {
			// Remove the editor by replacing it with the last element and then truncating
			sessions[i] = sessions[len(sessions)-1]
			editorSessions[registryID] = sessions[:len(sessions)-1]
			log.Printf("Editor %s (ID: %d) removed from registry %s",
				conn.Email, conn.PartnerID, registryID)
			break
		}
	}

	// If no more editors, schedule the registry for cleanup after some time
	if len(editorSessions[registryID]) == 0 {
		go scheduleRegistryCleanup(registryID)
	}
}

// scheduleRegistryCleanup schedules a registry for cleanup after a timeout
func scheduleRegistryCleanup(registryID string) {
	// Wait for some time (e.g., 1 hour) before cleaning up
	time.Sleep(1 * time.Hour)

	collaborativeMutex.Lock()
	defer collaborativeMutex.Unlock()

	// Check if there are still no editors
	if sessions, exists := editorSessions[registryID]; exists && len(sessions) == 0 {
		// Save registry to database before deleting from memory
		if content, exists := collaborativeRegistry[registryID]; exists {
			saveRegistryToDatabase(registryID, content)
			delete(collaborativeRegistry, registryID)
			delete(editorSessions, registryID)
			log.Printf("Registry %s cleaned up from memory", registryID)
		}
	}
}

// loadRegistryIfNeeded loads a registry from the database if it's not already in memory
func loadRegistryIfNeeded(registryID string) {
	collaborativeMutex.Lock()
	defer collaborativeMutex.Unlock()

	// Check if registry is already in memory
	if _, exists := collaborativeRegistry[registryID]; exists {
		return
	}

	// Try to load from database
	content, err := loadRegistryFromDatabase(registryID)
	if err != nil {
		// If not found or error, create a new empty registry
		log.Printf("Creating new empty registry with ID %s", registryID)
		collaborativeRegistry[registryID] = []byte("{}")
	} else {
		collaborativeRegistry[registryID] = content
		log.Printf("Loaded registry %s from database", registryID)
	}
}

// loadRegistryFromDatabase loads a registry from the database
func loadRegistryFromDatabase(registryID string) ([]byte, error) {
	// TODO: Implement database loading logic
	// This is a placeholder. You need to implement the actual database query.
	//
	// Example implementation:
	// ctx := context.Background()
	// registry, err := queries.GetRegistry(ctx, registryID)
	// if err != nil {
	//     return nil, err
	// }
	// return registry.Content, nil

	// For now, just return an empty JSON object if not found
	return []byte("{}"), nil
}

// Note: saveRegistryToDatabase was moved to init.go to avoid circular references

// sendFullDocumentToEditor sends the full document to a newly connected editor
func sendFullDocumentToEditor(registryID string, conn *EditorConnection) {
	collaborativeMutex.RLock()
	content, exists := collaborativeRegistry[registryID]
	collaborativeMutex.RUnlock()

	if !exists {
		log.Printf("Registry %s not found, cannot send to editor", registryID)
		return
	}

	message := EditorMessage{
		Type:      MessageTypeFullDocument,
		Content:   string(content),
		PartnerID: conn.PartnerID,
		Email:     conn.Email,
		Color:     conn.Color,
	}

	if err := conn.Connection.WriteJSON(message); err != nil {
		log.Printf("Error sending full document to editor %d: %v", conn.PartnerID, err)
	}
}

// notifyEditorJoined notifies all editors that a new editor has joined
func notifyEditorJoined(registryID string, newConn *EditorConnection) {
	collaborativeMutex.RLock()
	sessions, exists := editorSessions[registryID]
	collaborativeMutex.RUnlock()

	if !exists {
		return
	}

	message := EditorMessage{
		Type:      MessageTypeJoin,
		PartnerID: newConn.PartnerID,
		Email:     newConn.Email,
		Color:     newConn.Color,
		Tab:       newConn.Tab,
		CursorPos: newConn.CursorPos,
	}

	// Send to all editors except the new one
	for _, conn := range sessions {
		if conn.PartnerID != newConn.PartnerID {
			if err := conn.Connection.WriteJSON(message); err != nil {
				log.Printf("Error notifying editor %d about new join: %v", conn.PartnerID, err)
			}
		}
	}
}

// notifyEditorLeft notifies all editors that an editor has left
func notifyEditorLeft(registryID string, leftConn *EditorConnection) {
	collaborativeMutex.RLock()
	sessions, exists := editorSessions[registryID]
	collaborativeMutex.RUnlock()

	if !exists {
		return
	}

	message := EditorMessage{
		Type:      MessageTypeLeave,
		PartnerID: leftConn.PartnerID,
		Email:     leftConn.Email,
	}

	// Send to all remaining editors
	for _, conn := range sessions {
		if conn.PartnerID != leftConn.PartnerID {
			if err := conn.Connection.WriteJSON(message); err != nil {
				log.Printf("Error notifying editor %d about leave: %v", conn.PartnerID, err)
			}
		}
	}
}

// broadcastEditorMessage broadcasts a message to all editors in a session
func broadcastEditorMessage(registryID string, message EditorMessage, excludePartnerID int32) {
	collaborativeMutex.RLock()
	sessions, exists := editorSessions[registryID]
	collaborativeMutex.RUnlock()

	if !exists {
		return
	}

	for _, conn := range sessions {
		// Don't send to the originator of the message
		if conn.PartnerID != excludePartnerID {
			if err := conn.Connection.WriteJSON(message); err != nil {
				log.Printf("Error broadcasting to editor %d: %v", conn.PartnerID, err)
			}
		}
	}
}

// handleEditorMessages handles incoming messages from an editor
func handleEditorMessages(registryID string, conn *EditorConnection) {
	defer func() {
		// Clean up when the handler exits
		conn.Connection.Close()
		removeEditorFromSession(registryID, conn)
		notifyEditorLeft(registryID, conn)
	}()

	for {
		// Read message
		_, rawMessage, err := conn.Connection.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Parse message
		var message EditorMessage
		if err := json.Unmarshal(rawMessage, &message); err != nil {
			log.Printf("Error parsing message: %v", err)
			continue
		}

		// Ensure the message has the correct partner ID and email
		message.PartnerID = conn.PartnerID
		message.Email = conn.Email
		message.Color = conn.Color

		// Handle different message types
		switch message.Type {
		case MessageTypeEdit:
			// Update the registry content
			updateRegistryContent(registryID, message.Content)
			// Broadcast edit to other editors
			broadcastEditorMessage(registryID, message, conn.PartnerID)

		case MessageTypeCursorMove:
			// Update cursor position
			conn.CursorPos = message.CursorPos
			// Broadcast cursor position to other editors
			broadcastEditorMessage(registryID, message, conn.PartnerID)

		case MessageTypeTabChange:
			// Update tab
			conn.Tab = message.Tab
			// Broadcast tab change to other editors
			broadcastEditorMessage(registryID, message, conn.PartnerID)

		case MessageTypeLeave:
			// User is leaving, close connection
			return

		default:
			log.Printf("Unknown message type: %s", message.Type)
		}
	}
}

// updateRegistryContent updates the content of a registry
func updateRegistryContent(registryID string, content string) {
	collaborativeMutex.Lock()
	defer collaborativeMutex.Unlock()

	collaborativeRegistry[registryID] = []byte(content)
}

// JoinEditorRegistry handles requests to join an editor registry
func JoinEditorRegistry(ctx *gin.Context) {
	// Get payload (authenticated user)
	payload, err := GetPayload(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": ErrInvalidPayload})
		return
	}

	// Verify partner still exists and is active
	partner, err := queries.GetPartnerByEmail(ctx, payload.Email)
	if err != nil || !partner.Active {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": ErrAccountNotActive})
		return
	}

	// Get registry ID from query parameter
	registryID := ctx.Query("registry_id")
	if registryID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Registry ID is required"})
		return
	}

	// Upgrade connection to WebSocket
	conn, err := upgrader.Upgrade(ctx.Writer, ctx.Request, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection to WebSocket: %v", err)
		return
	}

	// Assign color to partner
	partnerColor := assignColorToPartner(payload.PartnerID)

	// Create editor connection
	editorConn := &EditorConnection{
		PartnerID:  payload.PartnerID,
		Email:      payload.Email,
		Connection: conn,
		CursorPos: CursorPosition{
			Line:   0,
			Column: 0,
		},
		Color: partnerColor,
		Tab:   1, // Default to first tab
	}

	// Add user to editor sessions
	addEditorToSession(registryID, editorConn)

	// Load registry if not already in memory
	loadRegistryIfNeeded(registryID)

	// Send full document to the newly connected editor
	sendFullDocumentToEditor(registryID, editorConn)

	// Notify all other editors that a new user has joined
	notifyEditorJoined(registryID, editorConn)

	// Handle WebSocket messages
	handleEditorMessages(registryID, editorConn)
}

// LeaveEditorRegistry handles requests to leave an editor registry
func LeaveEditorRegistry(ctx *gin.Context) {
	// The actual leave is handled when the WebSocket connection closes
	ctx.JSON(http.StatusOK, gin.H{"message": "Use WebSocket close to leave the registry"})
}

// SaveRegistry manually saves a registry to the database
func SaveRegistry(ctx *gin.Context) {
	// Authentication is handled by middleware, no need to check payload

	// Get registry ID from query parameter
	registryID := ctx.Query("registry_id")
	if registryID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Registry ID is required"})
		return
	}

	collaborativeMutex.RLock()
	content, exists := collaborativeRegistry[registryID]
	collaborativeMutex.RUnlock()

	if !exists {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "Registry not found"})
		return
	}

	// Save to database
	err := saveRegistryToDatabase(registryID, content)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save registry: %v", err)})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Registry saved successfully"})
}

// GetActiveEditors returns a list of active editors for a registry
func GetActiveEditors(ctx *gin.Context) {
	// Authentication is handled by middleware, no need to check payload

	// Get registry ID from query parameter
	registryID := ctx.Query("registry_id")
	if registryID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Registry ID is required"})
		return
	}

	collaborativeMutex.RLock()
	sessions, exists := editorSessions[registryID]
	collaborativeMutex.RUnlock()

	if !exists {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "Registry not found"})
		return
	}

	// Create a list of active editors
	type ActiveEditor struct {
		PartnerID int32          `json:"partner_id"`
		Email     string         `json:"email"`
		Color     string         `json:"color"`
		Tab       int            `json:"tab"`
		CursorPos CursorPosition `json:"cursor_pos"`
	}

	activeEditors := make([]ActiveEditor, 0, len(sessions))
	for _, conn := range sessions {
		activeEditors = append(activeEditors, ActiveEditor{
			PartnerID: conn.PartnerID,
			Email:     conn.Email,
			Color:     conn.Color,
			Tab:       conn.Tab,
			CursorPos: conn.CursorPos,
		})
	}

	ctx.JSON(http.StatusOK, gin.H{"editors": activeEditors})
}

// InitWSModule initializes the WebSocket module
func InitWSModule() {
	// Initialize collaborative editing maps if not already done
	if collaborativeRegistry == nil {
		collaborativeRegistry = make(map[string][]byte)
	}
	if editorSessions == nil {
		editorSessions = make(map[string][]*EditorConnection)
	}
	if partnerColors == nil {
		partnerColors = make(map[int32]string)
	}

	log.Println("WebSocket module initialized")
}

// Called from SetupAuthRoutes in auth.go
// This function is exposed for integration with the existing auth system
func wsInit() {
	// Initialize the WebSocket module
	InitWSModule()

	// Set up routes
	SetupWSRoutes(router, tokenMaker)
}

// SetupWSRoutes initializes WebSocket routes
// This function should be called from within SetupAuthRoutes
func SetupWSRoutes(router *gin.Engine, tokenMaker *pasetoMaker) {
	// WebSocket routes with authentication
	ws := router.Group("/ws").Use(wsAuthMiddleware())

	// Add editor routes
	ws.GET("/editor/join", JoinEditorRegistry)
	ws.GET("/editor/leave", LeaveEditorRegistry)

	// Add original connection handler for backward compatibility
	ws.GET("/connect", handleWebSocketConnection)

	// API routes for editor management (require auth)
	api := router.Group("/api").Use(authMiddleware())
	api.POST("/editor/save", SaveRegistry)
	api.GET("/editor/active", GetActiveEditors)
}
