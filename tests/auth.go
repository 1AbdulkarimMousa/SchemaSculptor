package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Configuration
const (
	BaseURL = "http://localhost:8000"
)

var (
	client    = &http.Client{Timeout: 10 * time.Second}
	authToken string
)

// Request/Response structures
type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type ActivateRequest struct {
	Email        string       `json:"email"`
	Verification Verification `json:"verification"`
}

type Verification struct {
	Code string `json:"code"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type ResetRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Email    string `json:"email"`
	Code     string `json:"code"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

// Helper functions
func readInput(prompt string) string {
	fmt.Print(prompt + " ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func makeRequest(method, endpoint string, payload interface{}) (map[string]interface{}, int, error) {
	// Convert payload to JSON
	var reqBody []byte
	var err error

	if payload != nil {
		reqBody, err = json.Marshal(payload)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to marshal payload: %v", err)
		}
	}

	// Create request
	req, err := http.NewRequest(method, BaseURL+endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	// Print request details
	fmt.Printf("\n📡 %s %s\n", method, endpoint)
	if payload != nil {
		prettyPayload, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Printf("Request Data:\n%s\n", string(prettyPayload))
	}

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read response body: %v", err)
	}

	// Parse response if JSON
	var responseData map[string]interface{}
	if len(body) > 0 {
		err = json.Unmarshal(body, &responseData)
		if err != nil {
			fmt.Printf("Response is not JSON: %s\n", string(body))
			responseData = map[string]interface{}{
				"raw": string(body),
			}
		}
	}

	// Print response
	fmt.Printf("Status: %d\n", resp.StatusCode)
	if len(body) > 0 {
		prettyResp, _ := json.MarshalIndent(responseData, "", "  ")
		fmt.Printf("Response:\n%s\n", string(prettyResp))
	}

	return responseData, resp.StatusCode, nil
}

func testRegistration() (string, string, bool) {
	fmt.Println("\n=== TESTING USER REGISTRATION ===")

	name := readInput("Enter your name:")
	email := readInput("Enter your email:")
	password := readInput("Enter your password:")

	payload := RegisterRequest{
		Name:     name,
		Email:    email,
		Password: password,
	}

	_, statusCode, err := makeRequest("POST", "/api/register", payload)
	if err != nil {
		fmt.Printf("❌ Registration error: %v\n", err)
		return email, password, false
	}

	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		fmt.Println("❌ Registration failed")
		return email, password, false
	}

	fmt.Println("✅ Registration successful!")
	return email, password, true
}

func testActivateAccount(email string) bool {
	fmt.Println("\n=== TESTING ACCOUNT ACTIVATION ===")

	code := readInput(fmt.Sprintf("Enter verification code sent to %s:", email))

	payload := ActivateRequest{
		Email: email,
		Verification: Verification{
			Code: code,
		},
	}

	_, statusCode, err := makeRequest("POST", "/api/register/activate", payload)
	if err != nil {
		fmt.Printf("❌ Activation error: %v\n", err)
		return false
	}

	if statusCode != http.StatusOK {
		fmt.Println("❌ Account activation failed")
		return false
	}

	fmt.Println("✅ Account activation successful!")
	return true
}

func testLogin(email, password string) bool {
	fmt.Println("\n=== TESTING LOGIN ===")

	payload := LoginRequest{
		Email:    email,
		Password: password,
	}

	response, statusCode, err := makeRequest("POST", "/api/login", payload)
	if err != nil {
		fmt.Printf("❌ Login error: %v\n", err)
		return false
	}

	if statusCode != http.StatusOK {
		fmt.Println("❌ Login failed")
		return false
	}

	// Extract token
	if token, ok := response["token"].(string); ok && token != "" {
		authToken = token
		fmt.Println("✅ Login successful! Token received.")
		return true
	} else {
		fmt.Println("❌ Login succeeded but no token received")
		return false
	}
}

func testTokenValidation() bool {
	if authToken == "" {
		fmt.Println("❌ No auth token available. Login first.")
		return false
	}

	fmt.Println("\n=== TESTING TOKEN VALIDATION ===")

	_, statusCode, err := makeRequest("GET", "/api/validify", nil)
	if err != nil {
		fmt.Printf("❌ Token validation error: %v\n", err)
		return false
	}

	if statusCode != http.StatusOK {
		fmt.Println("❌ Token validation failed")
		return false
	}

	fmt.Println("✅ Token validation successful!")
	return true
}

func testRequestPasswordReset(email string) bool {
	fmt.Println("\n=== TESTING PASSWORD RESET REQUEST ===")

	payload := ResetRequest{
		Email: email,
	}

	_, statusCode, err := makeRequest("POST", "/api/reset", payload)
	if err != nil {
		fmt.Printf("❌ Password reset request error: %v\n", err)
		return false
	}

	if statusCode != http.StatusOK {
		fmt.Println("❌ Password reset request failed")
		return false
	}

	fmt.Println("✅ Password reset request successful!")
	return true
}

func testResetPassword(email string) (string, bool) {
	fmt.Println("\n=== TESTING PASSWORD RESET ===")

	code := readInput(fmt.Sprintf("Enter reset code sent to %s:", email))
	newPassword := readInput("Enter new password:")

	payload := ResetPasswordRequest{
		Email:    email,
		Code:     code,
		Password: newPassword,
	}

	_, statusCode, err := makeRequest("POST", "/api/reset/activate", payload)
	if err != nil {
		fmt.Printf("❌ Password reset error: %v\n", err)
		return "", false
	}

	if statusCode != http.StatusOK {
		fmt.Println("❌ Password reset failed")
		return "", false
	}

	fmt.Println("✅ Password reset successful!")
	return newPassword, true
}

func testChangePasswordAuthenticated(email string) bool {
	fmt.Println("\n=== TESTING AUTHENTICATED PASSWORD CHANGE ===")

	if authToken == "" {
		fmt.Println("❌ No auth token available. Login first.")
		return false
	}

	// First request a verification code
	resetPayload := ResetRequest{
		Email: email,
	}

	_, statusCode, err := makeRequest("POST", "/api/reset", resetPayload)
	if err != nil {
		fmt.Printf("❌ Verification code request error: %v\n", err)
		return false
	}

	if statusCode != http.StatusOK {
		fmt.Println("❌ Verification code request failed")
		return false
	}

	code := readInput(fmt.Sprintf("Enter verification code sent to %s:", email))
	newerPassword := readInput("Enter new password:")

	payload := ResetPasswordRequest{
		Email:    email,
		Code:     code,
		Password: newerPassword,
	}

	_, statusCode, err = makeRequest("POST", "/api/reset/new", payload)
	if err != nil {
		fmt.Printf("❌ Authenticated password change error: %v\n", err)
		return false
	}

	if statusCode != http.StatusOK {
		fmt.Println("❌ Authenticated password change failed")
		return false
	}

	fmt.Println("✅ Authenticated password change successful!")
	return true
}

func testResendActivationCode(email string) bool {
	fmt.Println("\n=== TESTING RESEND ACTIVATION CODE ===")

	payload := ResetRequest{
		Email: email,
	}

	_, statusCode, err := makeRequest("POST", "/api/register/resend", payload)
	if err != nil {
		fmt.Printf("❌ Resend activation code error: %v\n", err)
		return false
	}

	if statusCode != http.StatusOK {
		fmt.Println("❌ Resend activation code failed")
		return false
	}

	fmt.Println("✅ Activation code resent successfully!")
	return true
}

func testResendPasswordResetCode(email string) bool {
	fmt.Println("\n=== TESTING RESEND PASSWORD RESET CODE ===")

	payload := ResetRequest{
		Email: email,
	}

	_, statusCode, err := makeRequest("POST", "/api/reset/resend", payload)
	if err != nil {
		fmt.Printf("❌ Resend password reset code error: %v\n", err)
		return false
	}

	if statusCode != http.StatusOK {
		fmt.Println("❌ Resend password reset code failed")
		return false
	}

	fmt.Println("✅ Password reset code resent successfully!")
	return true
}

func main() {
	fmt.Println("===== SchemaSculptor Auth API Tester =====")
	fmt.Println("This program will walk you through testing the authentication API.")
	fmt.Println("API Base URL:", BaseURL)
	fmt.Println("\nPress Enter to continue...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	// Start the test flow
	email, password, registered := testRegistration()
	if !registered {
		fmt.Println("Registration failed, but continuing with provided credentials.")
	}

	// Option to resend activation code
	if readInput("Do you want to test resending activation code? (y/n):") == "y" {
		testResendActivationCode(email)
	}

	activated := testActivateAccount(email)
	if !activated {
		fmt.Println("Account activation failed or skipped, but continuing.")
	}

	loggedIn := testLogin(email, password)
	if loggedIn {
		tokenValid := testTokenValidation()
		if !tokenValid {
			fmt.Println("Token validation failed, but continuing.")
		}
	} else {
		fmt.Println("Login failed, but continuing with password reset flow.")
	}

	resetRequested := testRequestPasswordReset(email)
	if resetRequested {
		// Option to resend password reset code
		if readInput("Do you want to test resending password reset code? (y/n):") == "y" {
			testResendPasswordResetCode(email)
		}

		newPassword, resetSuccessful := testResetPassword(email)
		if resetSuccessful {
			fmt.Println("Testing login with new password...")
			loggedIn = testLogin(email, newPassword)

			if loggedIn {
				testChangePasswordAuthenticated(email)
			}
		}
	}

	fmt.Println("\n===== AUTH API TESTING COMPLETE =====")
}
