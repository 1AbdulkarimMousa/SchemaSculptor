package handlers

// Stick to constants of string responses
// don't add functions to this file
// don't add msg handling to this file
// don't add msg checking to this file
// don't add msg logging to this file
// don't add msg recovery to this file
// this is intended to simplify gin{"key": RespMsg}
// handlers/responses.go

// You are only allowed to add constants to this file
const (
	// Success messages
	RespPasswordResetSuccess       = "Password has been reset successfully. You can now log in with your new password."
	RespPasswordChangeSuccess      = "Password has been changed successfully."
	RespEmailSent                  = "Email sent successfully."
	RespActivationSuccess          = "Your account has been activated successfully."
	RespRegistrationSuccess        = "Registration successful. Please check your email for verification code."
	RespVerificationResent         = "Verification email resent successfully."
	RespResetEmailSent             = "If a user with this email exists, a password reset email has been sent."
	RespAccountAlreadyActive       = "Account is already active. You can log in."
	RespVerificationRequired       = "Account not activated. Please check your email for verification code."
	RespVerificationResendCooldown = "Please wait before requesting another verification email."
)
