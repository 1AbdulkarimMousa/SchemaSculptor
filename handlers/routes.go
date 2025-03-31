// handlers/routes.go
package handlers

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// handleWebSocketConnection handles WebSocket connections
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

	// Implementation for WebSocket connection handling
	// This would typically involve upgrading the connection to WebSocket
	// and handling events

	log.Printf("WebSocket connection established for user: %s (ID: %d)", payload.Email, payload.PartnerID)

	// Here you would add the WebSocket upgrade logic
	// Example:
	// upgrader := websocket.Upgrader{
	//     ReadBufferSize:  1024,
	//     WriteBufferSize: 1024,
	//     CheckOrigin: func(r *http.Request) bool {
	//         return true
	//     },
	// }
	// conn, err := upgrader.Upgrade(ctx.Writer, ctx.Request, nil)
	// if err != nil {
	//     log.Printf("Failed to upgrade connection: %v", err)
	//     return
	// }
	// defer conn.Close()

	// Handle the WebSocket connection...
}

// userInfoRoute returns information about the authenticated user
func userInfoRoute(ctx *gin.Context) {
	// Get payload (authenticated user)
	payload, err := GetPayload(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": ErrInvalidPayload})
		return
	}

	// Get partner information
	partner, err := queries.GetPartnerByEmail(ctx, payload.Email)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrUserRetrievalFailed})
		return
	}

	// Return user info (excluding sensitive data)
	ctx.JSON(http.StatusOK, gin.H{
		"id":         partner.ID,
		"name":       partner.Name,
		"email":      partner.Email,
		"balance":    partner.Balance,
		"stripe_id":  partner.StripeID,
		"created_at": time.Now(), // This should come from the database; using current time as a placeholder
	})
}

// SetupAPIRoutes initializes API routes (excluding auth routes which are set up separately)
func SetupAPIRoutes(router *gin.Engine, tokenMaker *PasetoMaker) {
	// Add middleware for all API routes
	api := router.Group("/api")

	// Add authenticated API routes
	authenticatedApi := api.Group("").Use(authMiddleware(*tokenMaker))
	authenticatedApi.GET("/user", userInfoRoute)

	// Other API routes can be added here
}
