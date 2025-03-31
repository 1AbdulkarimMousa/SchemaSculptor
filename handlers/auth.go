// handlers/auth.go
package handlers

import (
	"context"
	"database/sql"
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

// Payload represents the token payload structure
type Payload struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	PartnerID int32     `json:"partner_id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	ExpiryAt  time.Time `json:"expiry_at"`
}

// NewPayload creates a new token payload with specified email and partner ID
func NewPayload(name string, email string, partnerID int32) (*Payload, error) {
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	payload := &Payload{
		ID:        tokenID,
		Name:      name,
		PartnerID: partnerID,
		Email:     email,
		CreatedAt: time.Now(),
		ExpiryAt:  time.Now().Add(time.Hour * 24),
	}
	return payload, nil
}

// Valid checks if the token has expired
func (payload *Payload) Valid() error {
	if time.Now().After(payload.ExpiryAt) {
		return errors.New(ErrTokenExpired)
	}
	return nil
}

// pasetoMaker handles PASETO token creation and verification
type pasetoMaker struct {
	paseto       *paseto.V2
	symmetricKey []byte
}

// newPaseto creates a new pasetoMaker with the given symmetric key
func newPaseto(symmetricKey string) (*pasetoMaker, error) {
	if len(symmetricKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("SymmetricKey too short should be: %v", chacha20poly1305.KeySize)
	}

	maker := &pasetoMaker{
		paseto:       paseto.NewV2(),
		symmetricKey: []byte(symmetricKey),
	}
	return maker, nil
}

// createToken generates a new token for a partner
func (maker *pasetoMaker) createToken(partner *db.Partner) (string, error) {
	payload, err := NewPayload(partner.Name, partner.Email, partner.ID)
	if err != nil {
		return "", err
	}
	return maker.paseto.Encrypt(maker.symmetricKey, payload, nil)
}

// verifyToken validates a token and returns its payload
func (maker *pasetoMaker) verifyToken(token string) (*Payload, error) {
	payload := &Payload{}
	err := maker.paseto.Decrypt(token, maker.symmetricKey, payload, nil)
	if err != nil {
		return nil, errors.New(ErrInvalidToken)
	}
	err = payload.Valid()
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// Helper types and functions
type accessKey struct {
	AccessToken string    `json:"token"`
	Email       string    `json:"email"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type VerificationActivation struct {
	Email string           `json:"email" validate:"required"`
	Data  VerificationData `json:"verification" validate:"required"`
}

type NewPassword struct {
	Email    string `json:"email" validate:"required"`
	Code     string `json:"code" validate:"required"`
	Password string `json:"password" validate:"required,min=8"`
}

// IsValidEmail checks if an email has a valid format
func IsValidEmail(email string) bool {
	return util.IsValidEmail(email)
}

// createNewVerification creates a new verification entry
func createNewVerification(email string) *VerificationData {
	verification := &VerificationData{
		Code:      strconv.Itoa(int(util.RandomInt(100000, 999999))),
		ExpiresAt: time.Now().Add(time.Hour),
		AgainAt:   time.Now().Add(time.Minute * 2),
		Type:      "Activation",
	}
	verifications[email] = *verification
	return verification
}

// authMiddleware verifies the authentication token in the request
func authMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authHeader := ctx.GetHeader(authorizationHeaderKey)
		if authHeader == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrNoHeader})
			return
		}

		fields := strings.Fields(authHeader)
		if len(fields) != 2 {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrInvalidBearer})
			ctx.Redirect(http.StatusFound, "/login")
			return
		}

		authType := strings.ToLower(fields[0])
		if authType != authorizationHeaderBearerType {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrUnsupportedAuth})
			return
		}

		token := fields[1]
		payload, err := tokenMaker.verifyToken(token)
		if err != nil {
			if err.Error() == ErrTokenExpired {
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrTokenExpired, "code": "token_expired"})
			} else {
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrInvalidToken})
			}
			return
		}

		ctx.Set("payload", payload)
		ctx.Next()
	}
}

// changePassword updates a user's password in the database
func changePassword(ctx context.Context, email string, newPassword string) error {
	partner, err := queries.GetPartnerByEmail(ctx, email)
	if err != nil {
		return errors.New(ErrUserRetrievalFailed)
	}

	hashedPassword, err := util.Hash(newPassword)
	if err != nil {
		return errors.New(ErrDBHashingPassword)
	}

	changePasswordParams := db.ChangePasswordParams{
		ID:       partner.ID,
		Password: hashedPassword,
	}

	err = queries.ChangePassword(ctx, changePasswordParams)
	if err != nil {
		return errors.New(ErrDBPasswordChange)
	}

	return nil
}

// Route handlers
// ==============

// register handles new user registration
func register(ctx *gin.Context) {
	var newPartner db.Partner
	if err := ctx.ShouldBindJSON(&newPartner); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err})
		return
	}

	if !IsValidEmail(newPartner.Email) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidEmail})
		return
	}

	if len(newPartner.Password) < 8 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidPasswordFormat})
		return
	}

	exists, err := queries.CheckUserEmail(ctx, newPartner.Email)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidEmailCheck})
		return
	}

	if exists {
		partner, err := queries.GetPartnerByEmail(ctx, newPartner.Email)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrUserRetrievalFailed})
			return
		}

		if !partner.Active {
			verification, exists := verifications[newPartner.Email]
			resend := true

			if exists {
				if verification.ExpiresAt.Before(time.Now()) {
					verification.ExpiresAt = time.Now().Add(time.Hour)
					verification.Code = strconv.Itoa(int(util.RandomInt(100000, 999999)))
				} else if !time.Now().After(verification.AgainAt) {
					resend = false
				}
				verification.AgainAt = time.Now().Add(time.Minute * 2)
				verifications[newPartner.Email] = verification
			} else {
				verification = *createNewVerification(newPartner.Email)
			}

			if resend {
				verification.resendVerificationEmail(newPartner.Email)
				ctx.JSON(http.StatusOK, gin.H{"message": RespVerificationRequired, "sent": true})
			} else {
				ctx.JSON(http.StatusOK, gin.H{"message": RespVerificationResendCooldown, "sent": false, "wait_until": verification.AgainAt})
			}
			return
		}

		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrAccountExists})
		return
	}

	hashedPassword, err := util.Hash(newPartner.Password)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": ErrDBHashingPassword})
		return
	}

	createPartnerParams := db.CreatePartnerParams{
		Name:     newPartner.Name,
		Email:    newPartner.Email,
		Password: hashedPassword,
		Balance:  0,
		Active:   false,
	}

	partner, err := queries.CreatePartner(ctx, createPartnerParams)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidEmailInsert})
		return
	}

	sendVerificationEmail(&partner)
	ctx.JSON(http.StatusOK, gin.H{"message": RespRegistrationSuccess, "email": partner.Email})
}

// login authenticates a user and provides an access token
func login(ctx *gin.Context, tokenMaker *pasetoMaker) {
	var credentials db.Partner
	if err := ctx.ShouldBindJSON(&credentials); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err})
		return
	}

	partner, err := queries.GetPartnerByEmail(ctx, credentials.Email)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidCredentials})
		return
	}

	if !partner.Active {
		ctx.JSON(http.StatusForbidden, gin.H{"error": ErrAccountNotActive})
		return
	}

	if err := util.Check(credentials.Password, partner.Password); err != nil {
		ctx.JSON(http.StatusForbidden, gin.H{"error": ErrIncorrectPassword})
		return
	}

	accessToken, err := tokenMaker.createToken(&partner)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	ctx.JSON(http.StatusOK, accessKey{
		AccessToken: accessToken,
		Email:       partner.Email,
		ExpiresAt:   time.Now().Add(time.Hour * 24),
	})
}

// ActivateAccountRoute activates a newly registered account
func ActivateAccountRoute(ctx *gin.Context, tokenMaker *pasetoMaker) {
	var unverified VerificationActivation
	if err := ctx.ShouldBindJSON(&unverified); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err})
		return
	}

	verification, ok := verifications[unverified.Email]
	if (!ok) || verification.Type != "Activation" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidVerification})
		return
	}

	if verification.Code != unverified.Data.Code {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidCode})
		return
	}

	if verification.ExpiresAt.Before(time.Now()) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrCodeExpired})
		return
	}

	partner, err := queries.GetPartnerByEmail(ctx, unverified.Email)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrUserRetrievalFailed})
		return
	}

	err = queries.ActivatePartner(ctx, partner.ID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrActivationFailed})
		return
	}

	err = queries.SetNewStripeAccount(ctx, db.SetNewStripeAccountParams{
		ID:       partner.ID,
		StripeID: sql.NullString{String: "", Valid: false},
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": ErrInternalServerError})
		return
	}

	delete(verifications, unverified.Email)
	accessToken, err := tokenMaker.createToken(&partner)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	ctx.JSON(http.StatusOK, accessKey{
		AccessToken: accessToken,
		Email:       partner.Email,
		ExpiresAt:   time.Now().Add(time.Hour * 24),
	})
}

// resendActivationRoute resends the activation code email
func resendActivationRoute(ctx *gin.Context) {
	var request db.Partner
	if err := ctx.ShouldBindJSON(&request); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err})
		return
	}

	if !IsValidEmail(request.Email) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidEmail})
		return
	}

	exists, err := queries.CheckUserEmail(ctx, request.Email)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidEmailCheck})
		return
	}

	if !exists {
		ctx.JSON(http.StatusOK, gin.H{"message": RespResetEmailSent, "sent": false})
		return
	}

	partner, err := queries.GetPartnerByEmail(ctx, request.Email)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrUserRetrievalFailed})
		return
	}

	if partner.Active {
		ctx.JSON(http.StatusOK, gin.H{"message": RespAccountAlreadyActive, "sent": false})
		return
	}

	verification, exists := verifications[request.Email]
	resend := true

	if exists {
		if verification.ExpiresAt.Before(time.Now()) {
			verification.ExpiresAt = time.Now().Add(time.Hour)
			verification.Code = strconv.Itoa(int(util.RandomInt(100000, 999999)))
			verification.Type = "Activation"
		} else if !time.Now().After(verification.AgainAt) {
			resend = false
		}
		verification.AgainAt = time.Now().Add(time.Minute * 2)
		verifications[request.Email] = verification
	} else {
		verification = *createNewVerification(request.Email)
	}

	if resend {
		verification.resendVerificationEmail(request.Email)
		ctx.JSON(http.StatusOK, gin.H{"message": RespVerificationResent, "sent": true})
	} else {
		ctx.JSON(http.StatusOK, gin.H{"message": RespVerificationResendCooldown, "sent": false, "wait_until": verification.AgainAt})
	}
}

// sendResetPasswordRoute sends a password reset code
func sendResetPasswordRoute(ctx *gin.Context) {
	var request db.Partner
	if err := ctx.ShouldBindJSON(&request); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err})
		return
	}

	if !IsValidEmail(request.Email) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidEmail})
		return
	}

	exists, err := queries.CheckUserEmail(ctx, request.Email)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidEmailCheck})
		return
	}

	if !exists {
		ctx.JSON(http.StatusOK, gin.H{"message": "If a user with this email exists, a password reset email has been sent.", "sent": true})
		return
	}

	verification, exists := verifications[request.Email]
	if exists {
		if verification.ExpiresAt.Before(time.Now()) {
			verification.ExpiresAt = time.Now().Add(time.Hour)
			verification.Code = strconv.Itoa(int(util.RandomInt(100000, 999999)))
			verification.Type = "PasswordReset"
			verifications[request.Email] = verification
		} else if !time.Now().After(verification.AgainAt) {
			ctx.JSON(http.StatusOK, gin.H{"message": "Please wait before requesting another password reset email.", "sent": false, "wait_until": verification.AgainAt})
			return
		}
		verification.AgainAt = time.Now().Add(time.Minute * 2)
		verifications[request.Email] = verification
	} else {
		verification = VerificationData{
			Code:      strconv.Itoa(int(util.RandomInt(100000, 999999))),
			ExpiresAt: time.Now().Add(time.Hour),
			AgainAt:   time.Now().Add(time.Minute * 2),
			Type:      "PasswordReset",
		}
		verifications[request.Email] = verification
	}

	sendResetCodeEmail(request.Email)
	ctx.JSON(http.StatusOK, gin.H{"message": "Password reset email sent successfully.", "sent": true})
}

// passwordResetRoute handles password reset with verification code
func passwordResetRoute(ctx *gin.Context) {
	var unverified NewPassword
	if err := ctx.ShouldBindJSON(&unverified); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err})
		return
	}

	if len(unverified.Password) < 8 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters long"})
		return
	}

	verification, ok := verifications[unverified.Email]
	if (!ok) || verification.Type != "PasswordReset" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidVerification})
		return
	}

	if verification.Code != unverified.Code {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidCode})
		return
	}

	if verification.ExpiresAt.Before(time.Now()) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrCodeExpired})
		return
	}

	err := changePassword(ctx, unverified.Email, unverified.Password)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err})
		return
	}

	partner, err := queries.GetPartnerByEmail(ctx, unverified.Email)
	if err == nil {
		user := &User{Partner: partner}
		user.sendResetPasswordEmail()
	}

	delete(verifications, unverified.Email)
	ctx.JSON(http.StatusOK, gin.H{"message": "Password has been reset successfully. You can now log in with your new password."})
}

// changePasswordRoute handles password change after successful login
func changePasswordRoute(ctx *gin.Context) {
	var unverified NewPassword
	if err := ctx.ShouldBindJSON(&unverified); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err})
		return
	}

	if len(unverified.Password) < 8 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidPasswordFormat})
		return
	}

	verification, ok := verifications[unverified.Email]
	if (!ok) || verification.Type != "PasswordReset" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidVerification})
		return
	}

	if verification.Code != unverified.Code {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidCode})
		return
	}

	if verification.ExpiresAt.Before(time.Now()) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrCodeExpired})
		return
	}

	err := changePassword(ctx, unverified.Email, unverified.Password)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err})
		return
	}

	delete(verifications, unverified.Email)
	ctx.JSON(http.StatusOK, gin.H{"message": RespPasswordChangeSuccess})
}

// resendResetPasswordRoute handles resending password reset emails
func resendResetPasswordRoute(ctx *gin.Context) {
	var request db.Partner
	if err := ctx.ShouldBindJSON(&request); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err})
		return
	}

	if !IsValidEmail(request.Email) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidEmail})
		return
	}

	exists, err := queries.CheckUserEmail(ctx, request.Email)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrInvalidEmailCheck})
		return
	}

	if !exists {
		ctx.JSON(http.StatusOK, gin.H{"message": RespResetEmailSent, "sent": true})
		return
	}

	verification, exists := verifications[request.Email]
	resend := true

	if exists && verification.Type == "PasswordReset" {
		if verification.ExpiresAt.Before(time.Now()) {
			verification.ExpiresAt = time.Now().Add(time.Hour)
			verification.Code = strconv.Itoa(int(util.RandomInt(100000, 999999)))
		} else if !time.Now().After(verification.AgainAt) {
			resend = false
		}
		verification.AgainAt = time.Now().Add(time.Minute * 2)
		verifications[request.Email] = verification
	} else {
		verification = VerificationData{
			Code:      strconv.Itoa(int(util.RandomInt(100000, 999999))),
			ExpiresAt: time.Now().Add(time.Hour),
			AgainAt:   time.Now().Add(time.Minute * 2),
			Type:      "PasswordReset",
		}
		verifications[request.Email] = verification
	}

	if resend {
		sendResetCodeEmail(request.Email)
		ctx.JSON(http.StatusOK, gin.H{"message": RespEmailSent, "sent": true})
	} else {
		ctx.JSON(http.StatusOK, gin.H{"message": RespVerificationResendCooldown, "sent": false, "wait_until": verification.AgainAt})
	}
}

// GetPayload retrieves partner information from context
func GetPayload(ctx *gin.Context) (*Payload, error) {
	payload, ok := ctx.Get("payload")
	if !ok {
		return nil, errors.New(ErrPayloadNotFound)
	}
	typedPayload, ok := payload.(*Payload)
	if !ok {
		return nil, errors.New(ErrInvalidPayload)
	}
	return typedPayload, nil
}

// validify validates if a token is still valid
func validify(ctx *gin.Context) {
	payload, err := GetPayload(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err})
		return
	}

	partner, err := queries.GetPartnerByEmail(ctx, payload.Email)
	if err != nil || !partner.Active {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": ErrAccountNotActive})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"is_valid": true, "expires_at": payload.ExpiryAt})
}

// RefreshTokenRoute refreshes an existing valid token
func refreshTokenRoute(ctx *gin.Context) {
	payload, err := GetPayload(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err})
		return
	}

	partner, err := queries.GetPartnerByEmail(ctx, payload.Email)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": ErrUserRetrievalFailed})
		return
	}

	if !partner.Active {
		ctx.JSON(http.StatusForbidden, gin.H{"error": ErrAccountNotActive})
		return
	}

	accessToken, err := tokenMaker.createToken(&partner)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	ctx.JSON(http.StatusOK, accessKey{
		AccessToken: accessToken,
		Email:       partner.Email,
		ExpiresAt:   time.Now().Add(time.Hour * 24),
	})
}

func wsAuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get token from query parameter
		token := ctx.Query("token")
		if token == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrMissingToken})
			return
		}

		// Verify the token using your existing PasetoMaker
		payload, err := tokenMaker.verifyToken(token)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrInvalidToken})
			return
		}

		// Set the payload in the context
		ctx.Set("payload", payload)
		ctx.Next()
	}
}

// initialize token maker and auth router with auth routes
func init() {
	tokenMaker, _ = newPaseto(util.PasetoKey)
	// Initialize router
	router = gin.Default()

	// Public routes
	router.POST("/api/register", register)
	router.POST("/api/register/activate", func(ctx *gin.Context) {
		ActivateAccountRoute(ctx, tokenMaker)
	})
	router.POST("/api/register/resend", resendActivationRoute)
	router.POST("/api/reset", sendResetPasswordRoute)
	router.POST("/api/reset/activate", passwordResetRoute)
	router.POST("/api/reset/resend", resendResetPasswordRoute)
	router.POST("/api/login", func(ctx *gin.Context) {
		login(ctx, tokenMaker)
	})

	// Protected routes
	auth := router.Group("/api").Use(authMiddleware())
	auth.POST("/reset/new", changePasswordRoute)
	auth.GET("/validify", validify)
	auth.POST("/refresh-token", refreshTokenRoute)

	wsInit() // sequential initialization for router then ws
}
