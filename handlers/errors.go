// handlers/errors.go
package handlers

import (
	"errors"
)

// Standard error types as constants
var (
	// Authentication errors
	ErrNoHeader           = errors.New("no authorization header was provided")
	ErrInvalidBearer      = errors.New("invalid or missing Bearer token")
	ErrUnsupportedAuth    = errors.New("authorization type not supported")
	ErrInvalidToken       = errors.New("access token not valid")
	ErrPayloadNotFound    = errors.New("payload not found")
	ErrInvalidPayload     = errors.New("invalid payload")
	ErrAccountExists      = errors.New("account already exists")
	ErrAccountNotActive   = errors.New("account not activated")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrIncorrectPassword  = errors.New("incorrect password")

	// Verification errors
	ErrInvalidVerification = errors.New("invalid verification")
	ErrInvalidCode         = errors.New("invalid code")
	ErrCodeExpired         = errors.New("code expired")
	ErrUserRetrievalFailed = errors.New("user retrieval failed")
	ErrActivationFailed    = errors.New("error while activation")
	ErrCooldownPeriod      = errors.New("please wait before requesting another verification email")

	// Database errors
	ErrInvalidEmail           = errors.New("invalid email")
	ErrInvalidEmailCheck      = errors.New("invalid email check")
	ErrInvalidEmailInsert     = errors.New("invalid email insert")
	ErrDBHashingPassword      = errors.New("error while hashing password")
	ErrDBPasswordChange       = errors.New("error while password change")
	ErrInvalidSelectParams    = errors.New("invalid selection parameters")
	ErrInvalidParamsAssertion = errors.New("invalid parameters assertion")

	// Server errors
	ErrInternalServerError = errors.New("internal server error")
	ErrInvalidJSON         = errors.New("invalid JSON payload")
	ErrNoPayload           = errors.New("no payload provided")

	// Deployment errors
	ErrSubdomainRequired    = errors.New("subdomain is required")
	ErrInvalidSubdomain     = errors.New("invalid subdomain format")
	ErrSubdomainTaken       = errors.New("subdomain is already taken")
	ErrInvalidServerVersion = errors.New("invalid server version")
	ErrInvalidServerPlan    = errors.New("invalid server plan")
	ErrNoBillingOption      = errors.New("no billing option provided")
	ErrInvalidSpecs         = errors.New("invalid server specifications")
	ErrInvalidUserServer    = errors.New("invalid user server")
	ErrDeploymentNotFound   = errors.New("deployment not found")
	ErrServerActionFailed   = errors.New("server action failed")
	ErrInvalidDestroyAction = errors.New("invalid destroy action")
	ErrInvalidAction        = errors.New("invalid action")
	ErrInvalidContext       = errors.New("invalid context")
)
