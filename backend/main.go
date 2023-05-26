package backend

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jghoshh/virtuo/backend/queue"
	"github.com/jghoshh/virtuo/backend/server"
	"github.com/jghoshh/virtuo/backend/server/auth"
	"github.com/jghoshh/virtuo/backend/server/notifications/email"
	"github.com/joho/godotenv"
)

func main() {
	// Load the .env file
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
	}

	// Read the environment variables
	signingKey := os.Getenv("JWT_SIGNING_KEY")
	serverURL := os.Getenv("SERVER_URL")
	dbURI := os.Getenv("MONGODB_URI")
	dbName := os.Getenv("TEST_DB_NAME")
	smtpEmail := os.Getenv("GOOGLE_EMAIL")
	smtpPassword := os.Getenv("GOOGLE_PASS")
	redisUrl := os.Getenv("REDIS_URL")
	rabbitMQURL := os.Getenv("RABBITMQ_URL")
	numEmailProducers := 1
	numEmailConsumers := 2
	ctx := context.Background() 
	
	email.InitEmailService(smtpEmail, smtpPassword)
	emailCache := queue.InitEmailCache(redisUrl)
	emailQueue := queue.BuildEmailQueue(rabbitMQURL, numEmailProducers, numEmailConsumers, emailCache)

	// Start the queue consumers
	_, _, err = emailQueue.StartConsumers(ctx)  
	if err != nil {
		log.Fatal("error starting queue consumers: ", err)
	}
	
	auth.InitAuth(dbName, dbURI, signingKey, emailQueue)
	go server.Start(serverURL, signingKey)
}