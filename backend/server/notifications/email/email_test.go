package email

import (
	"os"
	"testing"
	"log"
	"github.com/joho/godotenv"
	"fmt"
)

func TestMain(m *testing.M) {

	err := godotenv.Load("../../.env")
	if err != nil {
		fmt.Println("Error loading .env file")
	}

	smtpEmail := os.Getenv("GOOGLE_EMAIL")
	smtpPassword := os.Getenv("GOOGLE_PASS")

	if smtpEmail == "" || smtpPassword == "" {
		log.Fatalf("SMTP credentials or sender email not set in environment variables")
	}

	success, err := InitEmailService(smtpEmail, smtpPassword)
	if err != nil || !success {
		log.Fatalf("Failed to initialize email service: %v", err)
	}

	exitVal := m.Run()

	os.Exit(exitVal)
}

func TestSendEmail(t *testing.T) {
	to := "testemail1@gmail.com"
	token := "afljsdfklajsdkf"

	err := SendEmail(to, token)
	if err != nil {
		t.Errorf("Expected nil error, got '%v'", err)
	}
}
