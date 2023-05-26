package frontend

import (
	"fmt"
	"os"
	"github.com/jghoshh/virtuo/frontend/client"
	"github.com/jghoshh/virtuo/frontend/cmd"
	"github.com/joho/godotenv"
	"github.com/zalando/go-keyring"
)

func RunFrontend() {
	// Load the .env file
	err := godotenv.Load("frontend/.env")
	if err != nil {
		fmt.Println("Error loading .env file")
		fmt.Println("error here in frontend")
	}

	// Read the environment variables
	signingKey := os.Getenv("JWT_SIGNING_KEY")
	authToken := os.Getenv("AUTH_TOKEN")
	authTokenRefresh := os.Getenv("AUTH_TOKEN_REFRESH")
	serverURL := os.Getenv("SERVER_URL")

	// Client stuff
	keyring.Delete("Virtuo", authToken)
	keyring.Delete("Virtuo", authTokenRefresh)
	client.InitAuthClient(serverURL, signingKey, authToken, authTokenRefresh)
	cmd.InitAuthCmd()
	cmd.Execute()
}