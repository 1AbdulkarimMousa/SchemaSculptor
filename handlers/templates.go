// handlers/templates.go
package handlers

import (
	"github.com/valyala/fasttemplate"
)

// Email template constants
const (
	// VerificationEmailTemplate is used for account activation emails
	VerificationEmailTemplate = `
<!DOCTYPE html>
<html>
  <head>
  </head>
  <body>
    <h1>Verify Your SchemaSculptor Account</h1>
    <p>Hello {{NAME}},</p>
    <p>Thank you for signing up for our service. To complete your registration, please use the verification code below:</p>
    <p>Verification Code: <b>{{CODE}}</b></p>
    <p>This code will expire at: {{EXPIRES}}</p>
    <p>If you did not request this email verification, please ignore this message.</p>
    <p>Sincerely,</p>
    <p>SchemaSculptor</p>
  </body>
</html>
`

	// PasswordResetTemplate is used for password reset emails
	PasswordResetTemplate = `
<!DOCTYPE html>
<html>
  <head>
  </head>
  <body>
    <h1>Reset your SchemaSculptor Account Password</h1>
    <p>Hello {{NAME}},</p>
    <p>Below is the password reset code:</p>
    <p>Reset Code: <b>{{CODE}}</b></p>
    <p>This code will expire at: {{EXPIRES}}</p>
    <p>If you did not request this password reset, please ignore this message.</p>
    <p>Sincerely,</p>
    <p>SchemaSculptor</p>
  </body>
</html>
`

	// PasswordResetConfirmationTemplate is used to confirm successful password resets
	PasswordResetConfirmationTemplate = `
<!DOCTYPE html>
<html>
  <head>
  </head>
  <body>
    <h1>Password Reset Successful</h1>
    <p>Hello {{NAME}},</p>
    <p>Your password has been successfully reset on {{TIME}}.</p>
    <p>If you did not make this change, please contact support immediately.</p>
    <p>Sincerely,</p>
    <p>SchemaSculptor</p>
  </body>
</html>
`
)

// Template variables
var (
	verifyAccountTemplate        *fasttemplate.Template
	resetPasswordTemplate        *fasttemplate.Template
	passwordResetConfirmTemplate *fasttemplate.Template
)

// Initialize templates
func init() {
	verifyAccountTemplate = fasttemplate.New(VerificationEmailTemplate, "{{", "}}")
	resetPasswordTemplate = fasttemplate.New(PasswordResetTemplate, "{{", "}}")
	passwordResetConfirmTemplate = fasttemplate.New(PasswordResetConfirmationTemplate, "{{", "}}")
}
