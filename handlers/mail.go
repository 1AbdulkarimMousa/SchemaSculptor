// handlers/mail.go
package handlers

import (
	"log"
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

// Email template constants
const verifyMsg string = `
<!DOCTYPE html>
<html>
  <head>
  </head>
  <body>
    <h1>Verify Your Valutoria Account</h1>
    <p>Hello,</p>
    <p>Thank you for signing up for our service. To complete your registration, please verify your email address by clicking the link below:</p>
    <p>Verification Code: <b>[CODE]</b></p>
    <p>If you did not request this email verification, please ignore this message.</p>
    <p>Sincerely,</p>
    <p>Valutoria</p>
  </body>
</html>
`

const resetMsg string = `
<!DOCTYPE html>
<html>
</head>
<body>
<h1>Reset your Valutoria's Account Password</h1>
<p>Hello,</p>
<p>Below is the password reset code:</p>
<p>Reset Code: <b>[CODE]</b></p>
<p>If you did not request this email verification, please ignore this message.</p>
<p>Sincerely,</p>
<p>Valutoria</p>
</body>
</html>
`

// sendVerificationEmail sends a verification email to a newly registered user
func sendVerificationEmail(user *db.Partner) {
	verification := VerificationData{
		Code:      strconv.Itoa(int(util.RandomInt(100000, 999999))),
		ExpiresAt: time.Now().Add(time.Hour),
		AgainAt:   time.Now().Add(time.Minute * 2),
		Type:      "Activation",
	}
	verifications[user.Email] = verification

	message := verifyAccountTemplate.ExecuteString(map[string]interface{}{
		"NAME": user.Name,
		"CODE": verification.Code,
	})

	m := gomail.NewMessage()
	m.SetHeader("From", util.SMTPUser)
	m.SetHeader("To", user.Email)
	m.SetHeader("Subject", "Valutoria Account Activation")
	m.SetBody("text/html", message)

	if err := smtpDialer.DialAndSend(m); err != nil {
		log.Printf("Failed to send verification email: %v", err)
		// Don't panic, just log the error
	}
}

// resendVerificationEmail resends a verification email to an inactive user
func (verification *VerificationData) resendVerificationEmail(email string) {
	verificationData := verifications[email]

	message := verifyAccountTemplate.ExecuteString(map[string]interface{}{
		"CODE": verificationData.Code,
	})

	m := gomail.NewMessage()
	m.SetHeader("From", util.SMTPUser)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Valutoria Account Activation")
	m.SetBody("text/html", message)

	if err := smtpDialer.DialAndSend(m); err != nil {
		log.Printf("Failed to resend verification email: %v", err)
		// Don't panic, just log the error
	}
}

// sendResetCodeEmail sends a password reset code to a user
func (user *User) sendResetCodeEmail() {
	verification := VerificationData{
		Code:      strconv.Itoa(int(util.RandomInt(100000, 999999))),
		ExpiresAt: time.Now().Add(time.Hour),
		AgainAt:   time.Now().Add(time.Minute * 2),
		Type:      "PasswordReset",
	}
	verifications[user.Email] = verification

	message := resetPasswordTemplate.ExecuteString(map[string]interface{}{
		"NAME": user.Name,
		"CODE": verification.Code,
	})

	m := gomail.NewMessage()
	m.SetHeader("From", util.SMTPUser)
	m.SetHeader("To", user.Email)
	m.SetHeader("Subject", "Valutoria Password Reset Code")
	m.SetBody("text/html", message)

	if err := smtpDialer.DialAndSend(m); err != nil {
		log.Printf("Failed to send password reset email: %v", err)
		// Don't panic, just log the error
	}
}
