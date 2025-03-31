// handlers/errors.go
package handlers

// Stick to constants of string errors
// don't add functions to this file
// don't add error handling to this file
// don't add error checking to this file
// don't add error logging to this file
// don't add error recovery to this file
// this is intended to simplify gin{"error": ErrMsg}

// You are only allowed to add constants to this file
const (
	// Authentication errors
	ErrNoHeader           = "no authorization header was provided"
	ErrInvalidBearer      = "invalid or missing Bearer token"
	ErrMissingToken       = "missing token from query parameter"
	ErrUnsupportedAuth    = "authorization type not supported"
	ErrInvalidToken       = "access token not valid"
	ErrTokenExpired       = "token has expired"
	ErrPayloadNotFound    = "payload not found"
	ErrInvalidPayload     = "invalid payload"
	ErrAccountExists      = "account already exists"
	ErrAccountNotActive   = "account not activated"
	ErrInvalidCredentials = "invalid credentials"
	ErrIncorrectPassword  = "incorrect password"
	ErrRateLimitExceeded  = "rate limit exceeded, please try again later"

	// Verification errors
	ErrInvalidVerification   = "invalid verification"
	ErrInvalidCode           = "invalid verification code"
	ErrCodeExpired           = "verification code has expired"
	ErrUserRetrievalFailed   = "user retrieval failed"
	ErrActivationFailed      = "error while activating account"
	ErrCooldownPeriod        = "please wait before requesting another verification email"
	ErrNoVerificationFound   = "no verification found for this email"
	ErrWrongVerificationType = "wrong verification type"

	// Database errors
	ErrInvalidEmail           = "invalid email format"
	ErrInvalidEmailCheck      = "error checking email existence"
	ErrInvalidEmailInsert     = "error creating user account"
	ErrDBHashingPassword      = "error while hashing password"
	ErrDBPasswordChange       = "error while changing password"
	ErrInvalidSelectParams    = "invalid selection parameters"
	ErrInvalidParamsAssertion = "invalid parameters assertion"

	// Server errors
	ErrInternalServerError   = "internal server error"
	ErrInvalidJSON           = "invalid JSON payload"
	ErrNoPayload             = "no payload provided"
	ErrInvalidPasswordFormat = "password must be at least 8 characters long"
)
