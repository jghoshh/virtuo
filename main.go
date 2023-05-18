package main

import (
	"fmt"
	"os"
	"github.com/jghoshh/virtuo/client"
	"github.com/jghoshh/virtuo/cmd"
	"github.com/jghoshh/virtuo/server"
	"github.com/joho/godotenv"
	"github.com/zalando/go-keyring"
)

func main() {
	// Load the .env file
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
	}

	// Read the environment variables
	signingKey := os.Getenv("JWT_SIGNING_KEY")
	authToken := os.Getenv("AUTH_TOKEN")
	authTokenRefresh := os.Getenv("AUTH_TOKEN_REFRESH")
	serverURL := os.Getenv("SERVER_URL")
	dbURI := os.Getenv("MONGODB_URI")
	dbName := os.Getenv("TEST_DB_NAME")

	// Set default values if the environment variables are empty
	if signingKey == "" {
		signingKey = "your_default_signing_key"
	}
	if authToken == "" {
		authToken = "your_default_auth_token"
	}
	if authTokenRefresh == "" {
		authTokenRefresh = "your_default_auth_token_refresh"
	}

	keyring.Delete("Virtuo", authToken)
	keyring.Delete("Virtuo", authTokenRefresh)

	go server.Start(serverURL, signingKey)
	client.InitAuthClient(dbName, dbURI, serverURL, signingKey, authToken, authTokenRefresh)
	cmd.InitAuthCmd()
	cmd.Execute()
}
