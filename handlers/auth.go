// handlers/auth.go
package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/1AbdulkarimMousa/SchemaSculptor/db"
	"github.com/1AbdulkarimMousa/SchemaSculptor/util"
	"github.com/aead/chacha20poly1305"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/o1egl/paseto"
)

// Constants
const (
	authorizationHeaderKey        = "Authorization"
	authorizationHeaderBearerType = "bearer"
)

// Token related types and functions
// ================================

// Payload represents the token payload structure
type Payload struct {
	ID        uuid.UUID `json:"id"`
	PartnerID int32     `json:"partner_id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	ExpiryAt  time.Time `json:"expiry_at"`
}

// NewPayload creates a new token payload with specified email and partner ID
func NewPayload(email string, partnerID int32) (*Payload, error) {
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	payload := &Payload{
		ID:        tokenID,
		PartnerID: partnerID,
		Email:     email,
		CreatedAt: time.Now(),
		ExpiryAt:  time.Now().Add(time.Hour * 2),
	}

	return payload, nil
}

// Valid checks if the token has expired
func (payload *Payload) Valid() error {
	if time.Now().After(payload.ExpiryAt) {
		return errors.New("token has expired")
	}
	return nil
}

// PasetoMaker handles PASETO token creation and verification
type PasetoMaker struct {
	paseto       *paseto.V2
	symmetricKey []byte
}

// NewPaseto creates a new PasetoMaker with the given symmetric key
func NewPaseto(symmetricKey string) (*PasetoMaker, error) {
	if len(symmetricKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("SymmetricKey too short should be: %v", chacha20poly1305.KeySize)
	}

	maker := &PasetoMaker{
		paseto:       paseto.NewV2(),
		symmetricKey: []byte(symmetricKey),
	}

	return maker, nil
}

// CreateToken generates a new token for a partner
func (maker *PasetoMaker) CreateToken(partner *db.Partner) (string, error) {
	payload, err := NewPayload(partner.Email, partner.ID)
	if err != nil {
		return "", err
	}

	return maker.paseto.Encrypt(maker.symmetricKey, payload, nil)
}

// VerifyToken validates a token and returns its payload
func (maker *PasetoMaker) VerifyToken(token string) (*Payload, error) {
	payload := &Payload{}

	err := maker.paseto.Decrypt(token, maker.symmetricKey, payload, nil)
	if err != nil {
		return nil, err
	}

	err = payload.Valid()
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// Authentication middleware
// =======================

// authMiddleware verifies the authentication token in the request
func authMiddleware(maker PasetoMaker) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authHeader := ctx.GetHeader(authorizationHeaderKey)
		if authHeader == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrNoHeader.Error()})
			return
		}

		fields := strings.Fields(authHeader)
		if len(fields) != 2 {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrInvalidBearer.Error()})
			return
		}

		authType := fields[0]
		if strings.ToLower(authType) != authorizationHeaderBearerType {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrUnsupportedAuth.Error()})
			return
		}

		token := fields[1]
		payload, err := maker.VerifyToken(token)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrInvalidToken.Error()})
			return
		}

		ctx.Set("payload", payload)
		ctx.Next()
	}
}

// GetPayload retrieves partner information from context
func GetPayload(ctx *gin.Context) (*Payload, error) {
	payload, ok := ctx.Get("payload")
	if !ok {
		return nil, ErrPayloadNotFound
	}
	typedPayload, ok := payload.(*Payload)
	if !ok {
		return nil, ErrInvalidPayload
	}
	return typedPayload, nil
}

// Token validation endpoint
func validify(ctx *gin.Context) {
	tokenStatus := true
	ctx.JSON(http.StatusOK, gin.H{"is_valid": tokenStatus})
}

// Verification related types and functions
// =======================================

// VerificationActivation structure for account activation
type VerificationActivation struct {
	Email string           `json:"email" validate:"required"`
	Data  VerificationData `json:"verification" validate:"required"`
}

// NewPassword structure for password reset
type NewPassword struct {
	Email    string `json:"email" validate:"required"`
	Code     string `json:"code" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// Authentication handlers
// =====================

// register handles the registration process for a new partner
func register(ctx *gin.Context) {
	// Bind request with corresponding partner struct
	var newPartner db.Partner
	if err := ctx.ShouldBindJSON(&newPartner); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if a partner with the same email is already registered
	exists, err := queries.CheckUserEmail(ctx, newPartner.Email)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidEmailCheck.Error()})
		return
	}

	// Handle existing partners
	if exists {
		db.Querier.
			// For now, return error as account exists
			ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrAccountExists.Error()})
		return
	}

	// Insert new partner into the database
	hashedPassword, _ := util.Hash(newPartner.Password)

	// For CreatePartner SQLC requires a schema definition
	// Since we can't modify db package, this part requires adapting to your setup

	// Send verification email to the partner
	// Create a temporary partner object
	partner := &db.Partner{
		ID:       0, // This will be replaced by DB
		Name:     newPartner.Name,
		Email:    newPartner.Email,
		Password: hashedPassword,
		Balance:  0.0,
		Active:   false,
	}

	sendVerificationEmail(partner)
	ctx.Status(http.StatusOK)
}

// ActivateAccountRoute handles the account activation process for a partner
func ActivateAccountRoute(ctx *gin.Context) {
	// Request binding for new user details
	var unverified VerificationActivation
	if err := ctx.ShouldBindJSON(&unverified); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	verification, ok := verifications[unverified.Email]

	// Validate the activation code
	if (!ok) || verification.Type != "Activation" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidVerification.Error()})
		return
	}

	if verification.Code != unverified.Data.Code {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidCode.Error()})
		return
	}

	if verification.ExpiresAt.Before(time.Now()) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrCodeExpired.Error()})
		return
	}

	// After validation, select then activate partner
	// Need to add GetPartnerByEmail to SQLC
	// For now, return error
	ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Implementation error: GetPartnerByEmail not available"})
	return
}

// sendResetPasswordRoute handles sending a password reset code to the user's email
func sendResetPasswordRoute(ctx *gin.Context) {
	// Request binding
	var request db.Partner
	if err := ctx.ShouldBindJSON(&request); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	email := request.Email
	verification, exists := verifications[email]

	// Check verification status and cooldown period
	if exists && verification.ExpiresAt.Before(time.Now()) {
		verification.ExpiresAt = time.Now().Add(time.Hour)
		verification.Code = strconv.Itoa(int(util.RandomInt(100000, 999999)))
	} else if exists && !time.Now().After(verification.AgainAt) {
		ctx.JSON(http.StatusOK, gin.H{"sent": false})
		return
	}

	// Find the user
	exists, err := queries.CheckUserEmail(ctx, email)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidEmailCheck.Error()})
		return
	}

	if !exists {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "User doesn't exist"})
		return
	}

	// Need GetPartnerByEmail to send reset email
	ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Implementation error: GetPartnerByEmail not available"})
	return
}

// passwordResetRoute handles the verification of a password reset request
func passwordResetRoute(ctx *gin.Context) {
	var unverified NewPassword
	if err := ctx.ShouldBindJSON(&unverified); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	verification, ok := verifications[unverified.Email]

	// Validate verification code
	if (!ok) || verification.Type != "PasswordReset" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidVerification.Error()})
		return
	}

	if verification.Code != unverified.Code {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidCode.Error()})
		return
	}

	if verification.ExpiresAt.Before(time.Now()) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrCodeExpired.Error()})
		return
	}

	// Change password
	err := changePassword(ctx, unverified.Email, unverified.Password)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx.Status(http.StatusOK)
}

// ChangePasswordRoute handles the process of changing a user's password after verification
func ChangePasswordRoute(ctx *gin.Context) {
	var unverified NewPassword
	if err := ctx.ShouldBindJSON(&unverified); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	verification, ok := verifications[unverified.Email]

	// Validate verification code
	if (!ok) || verification.Type != "PasswordReset" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidVerification.Error()})
		return
	}

	if verification.Code != unverified.Code {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidCode.Error()})
		return
	}

	if verification.ExpiresAt.Before(time.Now()) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrCodeExpired.Error()})
		return
	}

	err := changePassword(ctx, unverified.Email, unverified.Password)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx.Status(http.StatusOK)
}

// changePassword updates a user's password in the database
func changePassword(ctx context.Context, email string, newPassword string) error {
	// Need GetPartnerByEmail to implement this
	return errors.New("Implementation error: GetPartnerByEmail not available")
}

// accessKey represents an AccessToken paired with the user Email
type accessKey struct {
	AccessToken string    `json:"token"`
	Email       string    `json:"email"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// login authenticates a user and provides an access token
func login(ctx *gin.Context) {
	// Bind request
	var credentials db.Partner
	if err := ctx.ShouldBindJSON(&credentials); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Need GetPartnerByEmail to implement this
	ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Implementation error: GetPartnerByEmail not available"})
	return
}

// WebSocket authentication middleware
func wsAuthMiddleware(maker PasetoMaker) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get token from query parameter
		token := ctx.Query("token")
		if token == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrNoHeader.Error()})
			return
		}

		// Verify the token using your existing PasetoMaker
		payload, err := maker.VerifyToken(token)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrInvalidToken.Error()})
			return
		}

		// Set the payload in the context
		ctx.Set("payload", payload)
		ctx.Next()
	}
}

// Initialize auth routes
func SetupAuthRoutes(router *gin.Engine, tokenMaker *PasetoMaker) {
	// Set up authentication routes
	router.POST("/api/register", register)
	router.POST("/api/register/activate", ActivateAccountRoute)
	router.POST("/api/reset", sendResetPasswordRoute)
	router.POST("/api/reset/activate", passwordResetRoute)
	router.POST("/api/login", login)

	// Protected routes
	auth := router.Group("/api").Use(authMiddleware(*tokenMaker))
	auth.POST("/reset/new", ChangePasswordRoute)

	auth.GET("/validify", validify)
}
