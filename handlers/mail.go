// handlers/mail.go
package handlers

import (
	"context"
	"strconv"
	"time"

	"github.com/1AbdulkarimMousa/SchemaSculptor/db"
	"github.com/1AbdulkarimMousa/SchemaSculptor/util"
	gomail "gopkg.in/mail.v2"
)

// VerificationData struct for tracking verification codes
type VerificationData struct {
	Code      string    `json:"code" validate:"required"`
	ExpiresAt time.Time `json:"expires_at"`
	AgainAt   time.Time `json:"again_at"`
	Type      string    `json:"type"` // Activation or PasswordReset
}

// User represents a partner with associated methods
type User struct{ db.Partner }

// sendVerificationEmail sends a verification email to a newly registered user
func sendVerificationEmail(user *db.Partner) {
	// Create a new verification code that expires in 1 hour
	verification := VerificationData{
		Code:      strconv.Itoa(int(util.RandomInt(100000, 999999))),
		ExpiresAt: time.Now().Add(time.Hour),
		AgainAt:   time.Now().Add(time.Minute * 2),
		Type:      "Activation",
	}
	verifications[user.Email] = verification

	message := verifyAccountTemplate.ExecuteString(map[string]interface{}{
		"NAME":    user.Name,
		"CODE":    verification.Code,
		"EXPIRES": verification.ExpiresAt.Format("2006-01-02 15:04:05"),
	})

	m := gomail.NewMessage()
	m.SetHeader("From", util.SMTPUser)
	m.SetHeader("To", user.Email)
	m.SetHeader("Subject", "Account Activation - SchemaSculptor")
	m.SetBody("text/html", message)

	smtpDialer.DialAndSend(m)
}

// resendVerificationEmail resends a verification email to an inactive user
func (verification *VerificationData) resendVerificationEmail(email string) {
	// Get partner by email to have access to the name
	partner, _ := queries.GetPartnerByEmail(context.Background(), email)

	// Update the verification in the global map to ensure it's current
	verifications[email] = *verification

	message := verifyAccountTemplate.ExecuteString(map[string]interface{}{
		"NAME":    partner.Name,
		"CODE":    verification.Code,
		"EXPIRES": verification.ExpiresAt.Format("2006-01-02 15:04:05"),
	})

	m := gomail.NewMessage()
	m.SetHeader("From", util.SMTPUser)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Account Activation - SchemaSculptor")
	m.SetBody("text/html", message)

	smtpDialer.DialAndSend(m)
}

// sendResetCodeEmail sends a password reset code to a user
func sendResetCodeEmail(email string) {
	verification, exists := verifications[email]

	if !exists || verification.Type != "PasswordReset" {
		// Create new verification if none exists or if it's not a password reset type
		verification = VerificationData{
			Code:      strconv.Itoa(int(util.RandomInt(100000, 999999))),
			ExpiresAt: time.Now().Add(time.Hour),
			AgainAt:   time.Now().Add(time.Minute * 2),
			Type:      "PasswordReset",
		}
	}

	// Update or add the verification to the global map
	verifications[email] = verification

	// Get partner by email to have access to the name
	partner, _ := queries.GetPartnerByEmail(context.Background(), email)

	message := resetPasswordTemplate.ExecuteString(map[string]interface{}{
		"NAME":    partner.Name,
		"CODE":    verification.Code,
		"EXPIRES": verification.ExpiresAt.Format("2006-01-02 15:04:05"),
	})

	m := gomail.NewMessage()
	m.SetHeader("From", util.SMTPUser)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Password Reset - SchemaSculptor")
	m.SetBody("text/html", message)

	smtpDialer.DialAndSend(m)
}

// sendResetPasswordEmail sends a confirmation email after password reset
func (user *User) sendResetPasswordEmail() {
	message := passwordResetConfirmTemplate.ExecuteString(map[string]interface{}{
		"NAME": user.Name,
		"TIME": time.Now().Format("2006-01-02 15:04:05"),
	})

	m := gomail.NewMessage()
	m.SetHeader("From", util.SMTPUser)
	m.SetHeader("To", user.Email)
	m.SetHeader("Subject", "Password Reset Successful - SchemaSculptor")
	m.SetBody("text/html", message)

	smtpDialer.DialAndSend(m)
}
