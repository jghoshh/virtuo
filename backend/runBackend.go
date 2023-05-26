package backend

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jghoshh/virtuo/backend/queue"
	"github.com/jghoshh/virtuo/backend/server"
	"github.com/jghoshh/virtuo/backend/server/auth"
	"github.com/jghoshh/virtuo/backend/server/notifications/email"
	"github.com/joho/godotenv"
)

// RunBackend is the main function that sets up and runs the backend server.
func RunBackend() {

	// Load the .env file.
	err := godotenv.Load("backend/.env")
	if err != nil {
		fmt.Println("Error loading .env file")
	}

	// Read the environment variables from the .env file using os.Getenv.
	signingKey := os.Getenv("JWT_SIGNING_KEY")    // JWT signing key for token generation
	serverURL := os.Getenv("SERVER_URL")          // The URL where the server is running
	dbURI := os.Getenv("MONGODB_URI")             // MongoDB database URI
	dbName := os.Getenv("TEST_DB_NAME")           // The name of the MongoDB database
	smtpEmail := os.Getenv("GOOGLE_EMAIL")        // The email address used for sending emails
	smtpPassword := os.Getenv("GOOGLE_PASS")      // The password for the email account
	redisUrl := os.Getenv("REDIS_URL")            // The Redis URL for caching emails
	rabbitMQURL := os.Getenv("RABBITMQ_URL")      // The URL for the RabbitMQ message broker
	numEmailProducers := 1                        // The number of email producers
	numEmailConsumers := 2                        // The number of email consumers
	ctx := context.Background()                   // Create a new context

	// Initialize the email service with the email and password
	email.InitEmailService(smtpEmail, smtpPassword)

	// Initialize the email cache using the Redis URL
	emailCache := queue.InitEmailCache(redisUrl)

	// Build the email queue using the RabbitMQ URL, number of producers and consumers, and email cache
	emailQueue := queue.BuildEmailQueue(rabbitMQURL, numEmailProducers, numEmailConsumers, emailCache)

	// Start the queue consumers
	_, _, err = emailQueue.StartConsumers(ctx)
	if err != nil {
		log.Fatal("error starting queue consumers: ", err)
	}

	// Initialize the authentication service
	auth.InitAuth(dbName, dbURI, signingKey, emailQueue)

	// Start the core server
	go server.Start(serverURL, signingKey)

	// Setting up the signal interrupt handler to gracefully shutdown our server
	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs  
		fmt.Println()  
		fmt.Println(sig)  
		os.Exit(0)
	}()


	select {}
}